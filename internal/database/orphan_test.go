package database

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFailInterruptedFlowsMarksActiveRows(t *testing.T) {
	dsn := os.Getenv("MIRAGE_BUDGET_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://mirage:mirage@127.0.0.1:55432/miragedb?sslmode=disable"
	}
	if err := pingDB(dsn); err != nil {
		_ = exec.Command("docker", "start", "mirage-budget-pg").Run()
	}
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = pingDB(dsn)
		if last == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if last != nil {
		t.Fatalf("postgres is required to prove interrupted-flow recovery: %v", last)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS flows (
		id UUID PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT '',
		target TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active',
		autonomy_level TEXT NOT NULL DEFAULT 'L3',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS tasks (
		id UUID PRIMARY KEY,
		flow_id UUID NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		result TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS subtasks (
		id UUID PRIMARY KEY,
		task_id UUID NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'queued',
		agent_type TEXT NOT NULL DEFAULT 'orchestrator',
		context TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	taskID := uuid.New()
	subID := uuid.New()
	pausedID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO flows (id, name, status) VALUES ($1, 'orphan', 'active'), ($2, 'paused', 'paused')`, id, pausedID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tasks (id, flow_id, name, status) VALUES ($1, $2, 'recon', 'running')`, taskID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO subtasks (id, task_id, name, status) VALUES ($1, $2, 'crawl', 'running')`, subID, taskID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM subtasks WHERE id = $1`, subID)
		_, _ = db.Exec(`DELETE FROM tasks WHERE id = $1`, taskID)
		_, _ = db.Exec(`DELETE FROM flows WHERE id IN ($1, $2)`, id, pausedID)
	})
	n, err := NewQueries(db).FailInterruptedFlows()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("reconciled=%d", n)
	}
	var status, taskStatus, subStatus, paused string
	if err := db.QueryRowContext(ctx, `SELECT status FROM flows WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%s", status)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM tasks WHERE id = $1`, taskID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "failed" {
		t.Fatalf("task status=%s", taskStatus)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM subtasks WHERE id = $1`, subID).Scan(&subStatus); err != nil {
		t.Fatal(err)
	}
	if subStatus != "failed" {
		t.Fatalf("subtask status=%s", subStatus)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM flows WHERE id = $1`, pausedID).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	if paused != "paused" {
		t.Fatalf("paused flow changed to %s", paused)
	}
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
