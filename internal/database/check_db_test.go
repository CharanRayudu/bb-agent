package database

import (
	"database/sql"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCheckDB(t *testing.T) {
	db, err := sql.Open("sqlite", "../../data/mirage.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM flow_events WHERE type='tool_result'").Scan(&count)
	if err != nil {
		t.Fatal(err)
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
