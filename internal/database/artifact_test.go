package database

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

func TestWorkspaceArtifactsDeduplicateAndReportsAreExplicit(t *testing.T) {
	db := openArtifactDB(t)
	q := NewQueries(db)
	flowID := uuid.New()
	first := uuid.New()
	second := uuid.New()
	if _, err := db.Exec(`INSERT INTO flows (id, name, target, status) VALUES ($1, 'scan', 'http://lab', 'active')`, flowID); err != nil {
		t.Fatal(err)
	}
	if err := q.SaveWorkspaceArtifact(flowID, &first, "scan.txt", "scan.txt", "nmap", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := q.SaveWorkspaceArtifact(flowID, &second, "scan.txt", "scan.txt", "nmap", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := q.SaveWorkspaceArtifact(flowID, &second, "nested/scan.txt", "nested/scan.txt", "nuclei", "ok"); err != nil {
		t.Fatal(err)
	}
	items, err := q.ListWorkspaceArtifacts(flowID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "nested/scan.txt" || items[1].Name != "scan.txt" {
		t.Fatalf("artifacts=%+v", items)
	}
	if items[1].Tool != "nmap" || items[1].Path != "scan.txt" {
		t.Fatalf("updated artifact=%+v", items[1])
	}
	got, err := q.GetWorkspaceArtifact(flowID, items[1].ID)
	if err != nil || got.Name != "scan.txt" {
		t.Fatalf("download lookup=%+v %v", got, err)
	}

	if _, err := q.GetFinalReport(flowID); err != sql.ErrNoRows {
		t.Fatalf("missing report err=%v", err)
	}
	if _, err := db.Exec(`INSERT INTO tasks (id, flow_id, name, status, result) VALUES ($1, $2, 'notes', 'done', 'unrelated task result')`, uuid.New(), flowID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetFinalReport(flowID); err != sql.ErrNoRows {
		t.Fatal("an unrelated task result was treated as the final report")
	}
	if _, err := db.Exec(`INSERT INTO tasks (id, flow_id, name, status, result) VALUES ($1, $2, 'Penetration Test', 'done', 'historical findings and evidence.txt')`, uuid.New(), flowID); err != nil {
		t.Fatal(err)
	}
	historical, err := q.GetFinalReport(flowID)
	if err != nil || historical != "historical findings and evidence.txt" {
		t.Fatalf("historical=%q %v", historical, err)
	}
	if err := q.SaveFinalReport(flowID, "final findings and evidence.txt"); err != nil {
		t.Fatal(err)
	}
	if err := q.SaveFinalReport(flowID, "final findings and evidence.txt"); err != nil {
		t.Fatal(err)
	}
	final, err := q.GetFinalReport(flowID)
	if err != nil || final != "final findings and evidence.txt" {
		t.Fatalf("final=%q %v", final, err)
	}
}

func openArtifactDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Connect("postgres://mirage:mirage@localhost:55432/miragedb?sslmode=disable")
	if err != nil {
		t.Fatalf("artifact test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("artifact test database ping: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS flows (
		id UUID PRIMARY KEY, name TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS tasks (
		id UUID PRIMARY KEY, flow_id UUID, name TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS artifacts (
		id UUID PRIMARY KEY, action_id UUID, flow_id UUID, type TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', content TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	DELETE FROM artifacts a USING artifacts b
		WHERE a.ctid > b.ctid AND a.flow_id = b.flow_id AND a.type = b.type AND a.name = b.name;
	CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_flow_type_name ON artifacts (flow_id, type, name);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
