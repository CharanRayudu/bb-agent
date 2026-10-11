package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestEngagementBudgetSurvivesRestart(t *testing.T) {
	dsn := disposablePostgres(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("postgres is required to prove budget restoration: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS engagement_authorizations (
		id TEXT PRIMARY KEY,
		engagement_id TEXT NOT NULL DEFAULT '',
		flow_id TEXT NOT NULL DEFAULT '',
		owner TEXT NOT NULL DEFAULT '',
		autonomy TEXT NOT NULL DEFAULT 'L3',
		expires_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		document JSONB NOT NULL DEFAULT '{}'
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE engagement_authorizations ADD COLUMN IF NOT EXISTS document JSONB NOT NULL DEFAULT '{}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS action_decisions (
		id TEXT PRIMARY KEY,
		action_id TEXT NOT NULL DEFAULT '',
		flow_id TEXT NOT NULL DEFAULT '',
		allowed BOOLEAN NOT NULL DEFAULT FALSE,
		code TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		idempotency_key TEXT NOT NULL DEFAULT '',
		actor_id TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS approval_requests (
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
	)`); err != nil {
		t.Fatal(err)
	}

	engagementID := "budget-" + uuid.NewString()
	flowID := "flow-" + uuid.NewString()
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	auth.ID = "auth:" + flowID
	auth.FlowID = flowID
	auth.EngagementID = engagementID
	auth.MaxRequests = 1
	auth.RequestsUsed = 0
	document, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO engagement_authorizations (id, engagement_id, flow_id, owner, autonomy, document)
		VALUES ($1, $2, $3, 'tester', 'L3', $4::jsonb)`, auth.ID, engagementID, flowID, string(document)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM engagement_authorizations WHERE engagement_id = $1`, engagementID)
	})

	book := policy.NewBook()
	mem := NewMemoryStore()
	if err := LoadState(ctx, db, book, mem); err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(book, NewDurableStore(mem, db), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	action := httpAct(t, "http://example.com/")
	action.FlowID = flowID
	action.EngagementID = engagementID
	action.IdempotencyKey = flowID + ":budget"
	if _, err := gw.Execute(ctx, action, func(context.Context, Action) (string, error) { return "ran", nil }); err != nil {
		t.Fatal(err)
	}

	restarted := policy.NewBook()
	if err := LoadState(ctx, db, restarted, NewMemoryStore()); err != nil {
		t.Fatal(err)
	}
	restored, ok := restarted.Snapshot(flowID)
	if !ok || restored.RequestsUsed != 1 {
		t.Fatalf("restart restored a spent budget: %+v ok=%v", restored, ok)
	}
	gw2 := NewGateway(restarted, NewDurableStore(NewMemoryStore(), db), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	action.IdempotencyKey = flowID + ":budget-2"
	_, err = gw2.Execute(ctx, action, func(context.Context, Action) (string, error) { return "ran", nil })
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("spent budget was usable after restart: %v", err)
	}
}

func disposablePostgres(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("MIRAGE_BUDGET_DATABASE_URL"); dsn != "" {
		return dsn
	}
	dsn := "postgres://mirage:mirage@127.0.0.1:55432/miragedb?sslmode=disable"
	if pingPostgres(dsn) == nil {
		return dsn
	}
	if _, err := exec.Command("docker", "version").CombinedOutput(); err != nil {
		t.Fatalf("postgres is required to prove budget restoration: %v", err)
	}
	_ = exec.Command("docker", "start", "mirage-budget-pg").Run()
	if pingPostgres(dsn) != nil {
		out, err := exec.Command("docker", "run", "-d", "--name", "mirage-budget-pg",
			"-e", "POSTGRES_USER=mirage", "-e", "POSTGRES_PASSWORD=mirage", "-e", "POSTGRES_DB=miragedb",
			"-p", "55432:5432", "postgres:16-alpine").CombinedOutput()
		if err != nil && pingPostgres(dsn) != nil {
			t.Fatalf("start postgres: %v\n%s", err, out)
		}
	}
	deadline := time.Now().Add(40 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if last = pingPostgres(dsn); last == nil {
			return dsn
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %v", last)
	return dsn
}

func pingPostgres(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}
