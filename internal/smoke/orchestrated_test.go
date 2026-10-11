package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/agent"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/server"
	"github.com/gorilla/websocket"
)

type scanStub struct {
	target   string
	toolCall string
	mu       sync.Mutex
	curled   bool
}

func (s *scanStub) Name() string { return "stub" }

func (s *scanStub) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var text strings.Builder
	for _, msg := range req.Messages {
		text.WriteString(msg.Content)
		text.WriteString("\n")
	}
	body := text.String()
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "skeptical penetration testing auditor"):
		return &llm.CompletionResponse{Content: "VALID: TRUE\nREASON: the scanner output shows the synthetic target responded."}, nil
	case strings.Contains(lower, "specialist specs") || strings.Contains(lower, "json array of specialist"):
		return &llm.CompletionResponse{Content: `{"specs":[{"type":"XSS","target":"` + s.target + `","context":"script parameter","hypothesis":"reflected script","proof":"request_response","priority":"medium"}]}`}, nil
	}
	s.mu.Lock()
	needCurl := strings.Contains(body, "Start Recon") && !s.curled
	if needCurl {
		s.curled = true
	}
	s.mu.Unlock()
	if needCurl {
		args := s.toolCall
		if args == "" {
			args = fmt.Sprintf(`{"tool":"curl","args":["-fsS","-o","evidence.txt","%s"],"timeout":20}`, s.target)
		}
		return &llm.CompletionResponse{ToolCalls: []models.ToolCall{{
			ID:        "call-scan",
			Name:      "run_security_tool",
			Arguments: args,
		}}}, nil
	}
	return &llm.CompletionResponse{ToolCalls: []models.ToolCall{{
		ID:        "call-done",
		Name:      "complete_task",
		Arguments: `{"summary":"synthetic target responded"}`,
	}}}, nil
}

func TestOrchestratedScanCompletesThroughTheAPI(t *testing.T) {
	if _, err := exec.Command("docker", "version").CombinedOutput(); err != nil {
		t.Fatalf("docker is required: %v", err)
	}
	ensureFirewallImage(t)
	hostIP := dockerHostGateway(t)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("http://%s:%d/", hostIP, port)
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go httpSrv.Serve(listener)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})

	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	t.Setenv("MIRAGE_TARGET_ALLOWLIST", hostIP)
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)

	stub := &scanStub{target: target}
	cfg := &config.Config{
		OpenAIModel:         "stub",
		OpenAITemperature:   0.1,
		ExecutionV2:         true,
		SandboxImage:        "mirage-firewall:local",
		FirewallHelperImage: "mirage-firewall:local",
	}
	app := server.New(cfg, db)
	app.UseLLMProvider(stub)
	planner := agent.NewPlanner(stub, nil, nil)
	planner.SetDecisionProvider(fixedDecision{}, 0.55)
	app.UseDecisionPlanner(planner)
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)

	wsURL := "ws" + strings.TrimPrefix(api.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	events := make(chan string, 32)
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			select {
			case events <- string(msg):
			default:
			}
		}
	}()

	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name":        "orchestrated",
		"description": "synthetic",
		"target":      target,
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatalf("create flow: %v body=%s", err, created)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM flow_events WHERE flow_id = $1`, flow.ID)
		_, _ = db.Exec(`DELETE FROM actions WHERE subtask_id IN (SELECT id FROM subtasks WHERE task_id IN (SELECT id FROM tasks WHERE flow_id = $1))`, flow.ID)
		_, _ = db.Exec(`DELETE FROM subtasks WHERE task_id IN (SELECT id FROM tasks WHERE flow_id = $1)`, flow.ID)
		_, _ = db.Exec(`DELETE FROM tasks WHERE flow_id = $1`, flow.ID)
		_, _ = db.Exec(`DELETE FROM brain_snapshots WHERE flow_id = $1`, flow.ID)
		_, _ = db.Exec(`DELETE FROM flows WHERE id = $1`, flow.ID)
	})

	status := waitForFlowStatus(t, api.URL, flow.ID, models.FlowStatusCompleted, 3*time.Minute)
	if status != models.FlowStatusCompleted {
		t.Fatalf("status=%s", status)
	}

	var output string
	if err := db.QueryRow(`SELECT COALESCE(string_agg(output, '\n'), '') FROM actions a JOIN subtasks s ON a.subtask_id = s.id JOIN tasks t ON s.task_id = t.id WHERE t.flow_id = $1`, flow.ID).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "[mirage-result]") || !strings.Contains(output, "status=ok") || !strings.Contains(output, "evidence.txt") {
		t.Fatalf("persisted tool output missing structured result:\n%s", output)
	}
	artifactBody := getBody(t, fmt.Sprintf("%s/api/flows/%s/artifacts", api.URL, flow.ID))
	var artifacts []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(artifactBody), &artifacts); err != nil || len(artifacts) == 0 {
		t.Fatalf("artifacts=%s err=%v", artifactBody, err)
	}
	fileRes, err := http.Get(fmt.Sprintf("%s/api/flows/%s/artifacts/%s", api.URL, flow.ID, artifacts[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, _ := io.ReadAll(fileRes.Body)
	fileRes.Body.Close()
	if fileRes.StatusCode != http.StatusOK || string(fileBytes) != "ok" {
		t.Fatalf("artifact download status=%d body=%q", fileRes.StatusCode, fileBytes)
	}
	reportBody := getBody(t, fmt.Sprintf("%s/api/flows/%s/report", api.URL, flow.ID))
	if !strings.Contains(reportBody, "Evidence files") && !strings.Contains(reportBody, "evidence.txt") {
		t.Fatalf("report missing evidence:\n%s", reportBody)
	}

	evidence := findFile(t, root, "evidence.txt")
	body, err := os.ReadFile(evidence)
	if err != nil || string(body) != "ok" {
		t.Fatalf("artifact %s = %q err=%v", evidence, body, err)
	}

	eventBody := getBody(t, fmt.Sprintf("%s/api/flows/%s/events", api.URL, flow.ID))
	if !strings.Contains(eventBody, "Vulnerability Assessment Complete") && !strings.Contains(eventBody, "complete") && !sawEvent(events, "complete") {
		t.Fatalf("progress events were not visible: %s", eventBody)
	}
}

func TestProductionScannersRunThroughTheOrchestrator(t *testing.T) {
	if _, err := exec.Command("docker", "image", "inspect", "mirage-tools:latest").CombinedOutput(); err != nil {
		t.Skip("mirage-tools:latest is not built")
	}
	checks := []struct {
		tool string
		args []string
	}{
		{"nmap", []string{"--version"}},
		{"nuclei", []string{"-version"}},
		{"ffuf", []string{"-V"}},
		{"sqlmap", []string{"--version"}},
		{"curl", []string{"--version"}},
	}
	for _, check := range checks {
		cmd := exec.Command("docker", "run", "--rm", "--entrypoint", check.tool, "mirage-tools:latest")
		cmd.Args = append(cmd.Args, check.args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", check.tool, err, out)
		}
		if len(strings.TrimSpace(string(out))) == 0 {
			t.Fatalf("%s produced no output", check.tool)
		}
	}

	hostIP := dockerHostGateway(t)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("http://%s:%d/", hostIP, port)
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go httpSrv.Serve(listener)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})
	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	t.Setenv("MIRAGE_TARGET_ALLOWLIST", hostIP)
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)
	stub := &scanStub{
		target:   target,
		toolCall: fmt.Sprintf(`{"tool":"nmap","args":["-sT","-p","%d","%s","-oN","scan.txt"],"timeout":90}`, port, hostIP),
	}
	cfg := &config.Config{
		OpenAIModel: "stub", ExecutionV2: true,
		SandboxImage: "mirage-tools:latest", FirewallHelperImage: "mirage-firewall:local",
	}
	app := server.New(cfg, db)
	app.UseLLMProvider(stub)
	planner := agent.NewPlanner(stub, nil, nil)
	planner.SetDecisionProvider(fixedDecision{}, 0.55)
	app.UseDecisionPlanner(planner)
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)
	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name": "tools", "description": "nmap", "target": target,
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatal(err)
	}
	status := waitForFlowStatus(t, api.URL, flow.ID, models.FlowStatusCompleted, 4*time.Minute)
	if status != models.FlowStatusCompleted {
		t.Fatalf("status=%s", status)
	}
	body := getBody(t, fmt.Sprintf("%s/api/flows/%s/artifacts", api.URL, flow.ID))
	if !strings.Contains(body, "scan.txt") {
		t.Fatalf("nmap artifact was not recorded: %s", body)
	}
	report := getBody(t, fmt.Sprintf("%s/api/flows/%s/report", api.URL, flow.ID))
	if !strings.Contains(report, "scan.txt") {
		t.Fatalf("report missing nmap evidence:\n%s", report)
	}
	nmapOut, err := os.ReadFile(findFile(t, root, "scan.txt"))
	if err != nil || !strings.Contains(string(nmapOut), "Nmap") {
		t.Fatalf("nmap output=%q err=%v", nmapOut, err)
	}
}

func TestCancelledScanDoesNotStayActive(t *testing.T) {
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)
	block := make(chan struct{})
	cfg := &config.Config{OpenAIModel: "stub", ExecutionV2: false}
	app := server.New(cfg, db)
	app.UseLLMProvider(blockingLLM{block: block})
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)
	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name": "cancel", "description": "stop", "target": "http://203.0.113.10/",
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(block)
		_, _ = db.Exec(`DELETE FROM flows WHERE id = $1`, flow.ID)
	})
	time.Sleep(300 * time.Millisecond)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/flows/%s/cancel", api.URL, flow.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel status=%d", res.StatusCode)
	}
	if got := flowStatus(t, api.URL, flow.ID); got != models.FlowStatusFailed {
		t.Fatalf("cancelled flow status=%s", got)
	}
}

type blockingLLM struct{ block <-chan struct{} }

func (blockingLLM) Name() string { return "blocking-stub" }

func (b blockingLLM) Complete(ctx context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.block:
		return &llm.CompletionResponse{Content: "stopped"}, nil
	}
}

func postJSON(t *testing.T, url string, body any) []byte {
	t.Helper()
	raw, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status=%d body=%s", url, res.StatusCode, payload)
	}
	return payload
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", url, res.StatusCode, payload)
	}
	return string(payload)
}

func waitForFlowStatus(t *testing.T, base string, id interface{ String() string }, want models.FlowStatus, limit time.Duration) models.FlowStatus {
	t.Helper()
	deadline := time.Now().Add(limit)
	var last models.FlowStatus
	for time.Now().Before(deadline) {
		last = flowStatus(t, base, id)
		if last == want || last == models.FlowStatusFailed {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

func flowStatus(t *testing.T, base string, id interface{ String() string }) models.FlowStatus {
	t.Helper()
	body := getBody(t, base+"/api/flows")
	var flows []models.Flow
	if err := json.Unmarshal([]byte(body), &flows); err != nil {
		t.Fatal(err)
	}
	for _, flow := range flows {
		if flow.ID.String() == id.String() {
			return flow.Status
		}
	}
	t.Fatalf("flow %s was not listed", id.String())
	return ""
}

func dockerHostGateway(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway", "mirage-firewall:local", "sh", "-c", "grep host.docker.internal /etc/hosts").CombinedOutput()
	if err != nil {
		t.Fatalf("resolve host gateway: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("host gateway output=%s", out)
	}
	return fields[0]
}

func findFile(t *testing.T, root, name string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Name() == name {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("%s was not written under %s", name, root)
	}
	return found
}

func sawEvent(events <-chan string, needle string) bool {
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg := <-events:
			if strings.Contains(strings.ToLower(msg), needle) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func prepareOrchestratorSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS tasks (
			id UUID PRIMARY KEY,
			flow_id UUID NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			result TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS subtasks (
			id UUID PRIMARY KEY,
			task_id UUID NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'queued',
			agent_type TEXT NOT NULL DEFAULT 'orchestrator',
			context TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS parent_subtask_id UUID`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'phase'`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS queue_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'medium'`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'`,
		`ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS context TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS actions (
			id UUID PRIMARY KEY,
			subtask_id UUID NOT NULL,
			type TEXT NOT NULL,
			input TEXT NOT NULL DEFAULT '',
			output TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'success',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS flow_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			flow_id UUID NOT NULL,
			type TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			metadata JSONB NOT NULL DEFAULT '{}',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS brain_snapshots (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			flow_id UUID NOT NULL UNIQUE,
			task_id UUID,
			stage TEXT NOT NULL DEFAULT 'runtime',
			revision INT NOT NULL DEFAULT 1,
			state JSONB NOT NULL DEFAULT '{}',
			summary JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS artifacts (
			id UUID PRIMARY KEY,
			action_id UUID,
			flow_id UUID NOT NULL,
			type TEXT NOT NULL DEFAULT 'workspace',
			name TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS target_memory (
			id UUID PRIMARY KEY,
			target TEXT NOT NULL,
			domain TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL DEFAULT '',
			insight TEXT NOT NULL DEFAULT '',
			flow_id UUID
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}
