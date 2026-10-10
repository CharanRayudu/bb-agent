package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/agent"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/decision"
	"github.com/bb-agent/mirage/internal/docker"
	"github.com/bb-agent/mirage/internal/execution"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/server"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
)

type stubLLM struct{}

func (stubLLM) Name() string { return "stub" }

func (stubLLM) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{Content: `{"objective":"confirm the synthetic target","hypothesis":"the peer responds","phases":[{"id":1,"title":"Scan","status":"pending","criteria":"artifact saved"}]}`}, nil
}

type fixedDecision struct{}

func (fixedDecision) Decide(context.Context, decision.Request) (decision.Response, error) {
	confidence := 0.93
	return decision.Response{
		Model:   "decision-1",
		Latency: time.Millisecond,
		Answers: map[string]decision.Answer{
			"specialist": {Type: decision.TypeChoice, Choice: "XSS", Confidence: &confidence},
		},
	}, nil
}

func TestStackReachesAScannerArtifact(t *testing.T) {
	if _, err := exec.Command("docker", "version").CombinedOutput(); err != nil {
		t.Fatalf("docker is required for the stack smoke: %v", err)
	}
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)

	cfg := &config.Config{OpenAIModel: "stub", OpenAITemperature: 0.1, ExecutionV2: true, FirewallHelperImage: "mirage-firewall:local", SandboxImage: "mirage-tools:latest"}
	api := httptest.NewServer(server.New(cfg, db).Handler())
	defer api.Close()

	health, err := http.Get(api.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d", health.StatusCode)
	}
	wsURL := "ws" + strings.TrimPrefix(api.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	flow, err := database.NewQueries(db).CreateFlow("smoke", "stack", "http://synthetic.local", "L3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM flows WHERE id = $1`, flow.ID) })

	list, err := http.Get(api.URL + "/api/flows")
	if err != nil {
		t.Fatal(err)
	}
	defer list.Body.Close()
	var flows []models.Flow
	if err := json.NewDecoder(list.Body).Decode(&flows); err != nil {
		t.Fatal(err)
	}
	if !containsFlow(flows, flow.ID) {
		t.Fatal("API did not return the flow stored in Postgres")
	}

	planner := agent.NewPlanner(stubLLM{}, nil, nil)
	plan, err := planner.CreatePlan(context.Background(), flow.ID, flow.Target, "peer responds on port 8080", &agent.Brain{})
	if err != nil || plan.Objective == "" || len(plan.Phases) == 0 {
		t.Fatalf("stub plan=%+v err=%v", plan, err)
	}
	planner.SetDecisionProvider(fixedDecision{}, 0.55)
	selected := planner.SelectSpecialist(context.Background(), "the search parameter reflects a script tag", flow.Target)
	if selected.Source != decision.SourceModel || selected.Specialist != "XSS" {
		t.Fatalf("decision routing=%+v", selected)
	}

	ensureFirewallImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	fs, err := docker.NewFlowSandbox("", "mirage-firewall:local")
	if err != nil {
		t.Fatal(err)
	}
	flowKey := flow.ID.String()
	workspace, err := execution.EnsureWorkspace(flowKey)
	if err != nil {
		t.Fatal(err)
	}
	sandboxCfg := docker.DefaultFlowConfig()
	sandboxCfg.Image = "mirage-firewall:local"
	sandboxCfg.MemoryLimit = 128 << 20
	sandboxCfg.CPULimit = 5e8
	sandboxCfg.WorkspaceHost = workspace
	if _, err := fs.CreateForFlow(ctx, flowKey, docker.ProfileDefault, sandboxCfg); err != nil {
		t.Fatal(err)
	}
	peerName := "mirage-smoke-peer-" + flow.ID.String()[:8]
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = exec.Command("docker", "rm", "-f", peerName).Run()
		_ = fs.DestroyForFlow(clean, flowKey)
	})
	peer := exec.Command("docker", "run", "-d", "--name", peerName, "--network", fs.NetworkName(flowKey), "mirage-firewall:local", "sh", "-c", `while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok' | nc -l -p 8080; done`)
	if out, err := peer.CombinedOutput(); err != nil {
		t.Fatalf("start synthetic target: %v\n%s", err, out)
	}
	peerIP := strings.TrimSpace(mustInspectIP(t, peerName))
	runner := docker.FlowRunner{Sandbox: fs, Image: "mirage-firewall:local"}
	scanned, err := runner.Execute(ctx, execution.ToolRequest{
		FlowID:         flowKey,
		Argv:           []string{"curl", "-fsS", "http://" + peerIP + ":8080/"},
		TimeoutSeconds: 20,
	})
	if err != nil || scanned.ExitCode != 0 || !strings.Contains(scanned.Stdout, "ok") || scanned.Duration <= 0 {
		t.Fatalf("scanner result=%+v err=%v", scanned, err)
	}
	saved, err := runner.Execute(ctx, execution.ToolRequest{
		FlowID:         flowKey,
		Argv:           []string{"sh", "-c", "printf smoke > /workspace/evidence.txt"},
		TimeoutSeconds: 15,
	})
	if err != nil || saved.ExitCode != 0 {
		t.Fatalf("artifact write=%+v err=%v", saved, err)
	}
	body, err := os.ReadFile(filepath.Join(workspace, "evidence.txt"))
	if err != nil || string(body) != "smoke" {
		t.Fatalf("artifact=%q err=%v paths=%v", body, err, saved.Artifacts)
	}
	if err := database.NewQueries(db).UpdateFlowStatus(flow.ID, models.FlowStatusCompleted); err != nil {
		t.Fatal(err)
	}
	again, err := http.Get(api.URL + "/api/flows")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Body.Close()
	flows = nil
	if err := json.NewDecoder(again.Body).Decode(&flows); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range flows {
		if item.ID == flow.ID && item.Status == models.FlowStatusCompleted {
			found = true
		}
	}
	if !found {
		t.Fatal("completed scan was not visible through the API")
	}
}

func containsFlow(flows []models.Flow, id uuid.UUID) bool {
	for _, flow := range flows {
		if flow.ID == id {
			return true
		}
	}
	return false
}

func mustInspectIP(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect %s: %v\n%s", name, err, out)
	}
	return string(out)
}

func ensureFirewallImage(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "image", "inspect", "mirage-firewall:local").Run(); err == nil {
		return
	}
	out, err := exec.Command("docker", "build", "-t", "mirage-firewall:local", filepath.Join("..", "..", "build", "egress-fixture")).CombinedOutput()
	if err != nil {
		t.Fatalf("build firewall image: %v\n%s", err, out)
	}
}

func openSmokeDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("MIRAGE_BUDGET_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://mirage:mirage@127.0.0.1:55432/miragedb?sslmode=disable"
	}
	if err := pingDB(dsn); err != nil {
		_ = exec.Command("docker", "start", "mirage-budget-pg").Run()
	}
	if pingDB(dsn) != nil {
		out, err := exec.Command("docker", "run", "-d", "--name", "mirage-budget-pg",
			"-e", "POSTGRES_USER=mirage", "-e", "POSTGRES_PASSWORD=mirage", "-e", "POSTGRES_DB=miragedb",
			"-p", "55432:5432", "postgres:16-alpine").CombinedOutput()
		if err != nil && pingDB(dsn) != nil {
			t.Fatalf("start postgres: %v\n%s", err, out)
		}
	}
	deadline := time.Now().Add(40 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if last = pingDB(dsn); last == nil {
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			return db
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %v", last)
	return nil
}

func pingDB(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

func prepareSmokeSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS flows (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			autonomy_level TEXT NOT NULL DEFAULT 'L3',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE flows ADD COLUMN IF NOT EXISTS autonomy_level TEXT NOT NULL DEFAULT 'L3'`,
		`CREATE TABLE IF NOT EXISTS engagement_authorizations (
			id TEXT PRIMARY KEY,
			document JSONB NOT NULL DEFAULT '{}'
		)`,
		`CREATE TABLE IF NOT EXISTS approval_requests (
			id TEXT PRIMARY KEY,
			action_key TEXT NOT NULL DEFAULT '',
			flow_id TEXT NOT NULL DEFAULT '',
			phase TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			actor TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			method TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			digest TEXT NOT NULL DEFAULT '',
			risk TEXT NOT NULL DEFAULT '',
			capability TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}
