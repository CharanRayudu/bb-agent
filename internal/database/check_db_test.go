package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCheckDB(t *testing.T) {
	dbPath := filepath.Clean(filepath.Join("..", "..", "data", "mirage.db"))
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("skipping database inspection test; fixture unavailable at %s: %v", dbPath, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM flow_events WHERE type='tool_result'").Scan(&count)
	if err != nil {
		t.Skipf("skipping database inspection test; query fixture unavailable: %v", err)
	}

	fmt.Printf("\n=== RESULT: %d tool_result events ===\n", count)

	if count > 0 {
		rows, _ := db.Query("SELECT content, metadata FROM flow_events WHERE type='tool_result' LIMIT 5")
		for rows.Next() {
			var content, metadata string
			rows.Scan(&content, &metadata)
			fmt.Printf("Metadata: %s\n", metadata)
		}
	}
}
