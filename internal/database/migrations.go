package database

import (
	"database/sql"
	"fmt"
	"log"
	"sort"
	"time"
)

// Migration represents a single schema migration.
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// MigrationRecord tracks applied migrations.
type MigrationRecord struct {
	Version     int       `json:"version"`
	Description string    `json:"description"`
	AppliedAt   time.Time `json:"applied_at"`
}

// VersionedMigrations returns all schema migrations in order.
func VersionedMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Initial schema (flows, tasks, subtasks, actions, artifacts, memories, events)",
			SQL:         "", // Already handled by legacy RunMigrations
		},
		{
			Version:     2,
			Description: "Add long_term_memory table for cross-flow learning",
			SQL: `CREATE TABLE IF NOT EXISTS long_term_memory (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				target TEXT NOT NULL,
				category TEXT NOT NULL,
				content TEXT NOT NULL,
				tech_stack TEXT DEFAULT '',
				flow_id UUID,
				created_at TIMESTAMP DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_ltm_target ON long_term_memory(target);
			CREATE INDEX IF NOT EXISTS idx_ltm_category ON long_term_memory(category);
			CREATE INDEX IF NOT EXISTS idx_ltm_tech ON long_term_memory(tech_stack);`,
		},
		{
			Version:     3,
			Description: "Add dead_letter_queue table for failed specialist items",
			SQL: `CREATE TABLE IF NOT EXISTS dead_letter_queue (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				flow_id UUID NOT NULL,
				queue_name TEXT NOT NULL,
				payload JSONB NOT NULL DEFAULT '{}',
				error TEXT NOT NULL DEFAULT '',
				retry_count INT DEFAULT 0,
				created_at TIMESTAMP DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_dlq_flow ON dead_letter_queue(flow_id);`,
		},
		{
			Version:     4,
			Description: "Add api_keys and users tables for JWT auth",
			SQL: `CREATE TABLE IF NOT EXISTS api_keys (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				name TEXT NOT NULL,
				key_hash TEXT NOT NULL UNIQUE,
				role TEXT NOT NULL DEFAULT 'operator',
				created_by TEXT DEFAULT '',
				last_used TIMESTAMP,
				expires_at TIMESTAMP,
				created_at TIMESTAMP DEFAULT NOW()
			);
			CREATE TABLE IF NOT EXISTS users (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				username TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT 'operator',
				created_at TIMESTAMP DEFAULT NOW()
			);`,
		},
		{
			Version:     5,
			Description: "APTS AL: Add autonomy_level column to flows table",
			SQL:         `ALTER TABLE flows ADD COLUMN IF NOT EXISTS autonomy_level TEXT NOT NULL DEFAULT 'L3';`,
		},
		{
			Version:     6,
			Description: "Engagement authorizations, action decisions, and approval requests",
			SQL: `CREATE TABLE IF NOT EXISTS engagement_authorizations (
				id TEXT PRIMARY KEY,
				engagement_id TEXT NOT NULL DEFAULT '',
				flow_id TEXT NOT NULL DEFAULT '',
				owner TEXT NOT NULL DEFAULT '',
				autonomy TEXT NOT NULL DEFAULT 'L3',
				expires_at TIMESTAMPTZ,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_engagement_auth_flow ON engagement_authorizations(flow_id);
			CREATE TABLE IF NOT EXISTS action_decisions (
				id TEXT PRIMARY KEY,
				action_id TEXT NOT NULL DEFAULT '',
				flow_id TEXT NOT NULL DEFAULT '',
				allowed BOOLEAN NOT NULL DEFAULT FALSE,
				code TEXT NOT NULL DEFAULT '',
				reason TEXT NOT NULL DEFAULT '',
				idempotency_key TEXT NOT NULL DEFAULT '',
				actor_id TEXT NOT NULL DEFAULT '',
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_action_decisions_flow ON action_decisions(flow_id);
			CREATE TABLE IF NOT EXISTS approval_requests (
				id TEXT PRIMARY KEY,
				action_key TEXT NOT NULL DEFAULT '',
				flow_id TEXT NOT NULL DEFAULT '',
				phase TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'pending',
				actor TEXT NOT NULL DEFAULT '',
				reason TEXT NOT NULL DEFAULT '',
				expires_at TIMESTAMPTZ,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_approval_requests_flow ON approval_requests(flow_id);`,
		},
		{
			Version:     7,
			Description: "Persist full authorization documents and approval action metadata",
			SQL: `ALTER TABLE engagement_authorizations ADD COLUMN IF NOT EXISTS document JSONB NOT NULL DEFAULT '{}';
			ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT '';
			ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT '';
			ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS digest TEXT NOT NULL DEFAULT '';
			ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS risk TEXT NOT NULL DEFAULT '';
			ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS capability TEXT NOT NULL DEFAULT '';`,
		},
		{
			Version:     8,
			Description: "One workspace artifact row per flow and relative path",
			SQL: `DELETE FROM artifacts a USING artifacts b
				WHERE a.ctid > b.ctid AND a.flow_id = b.flow_id AND a.type = b.type AND a.name = b.name;
			CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_flow_type_name ON artifacts (flow_id, type, name);`,
		},
	}
}

// RunVersionedMigrations applies only pending migrations.
func RunVersionedMigrations(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INT PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migration tracking table: %w", err)
	}

	applied := make(map[int]bool)
	rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err == nil {
			applied[v] = true
		}
	}

	migrations := VersionedMigrations()
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })

	pendingCount := 0
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}

		if m.SQL != "" {
			if _, err := db.Exec(m.SQL); err != nil {
				return fmt.Errorf("migration v%d (%s) failed: %w", m.Version, m.Description, err)
			}
		}

		_, err := db.Exec(
			`INSERT INTO schema_migrations (version, description) VALUES ($1, $2)`,
			m.Version, m.Description,
		)
		if err != nil {
			return fmt.Errorf("failed to record migration v%d: %w", m.Version, err)
		}

		pendingCount++
		log.Printf("[migration] Applied v%d: %s", m.Version, m.Description)
	}

	if pendingCount == 0 {
		log.Println("[migration] Schema is up to date")
	} else {
		log.Printf("[migration] Applied %d new migration(s)", pendingCount)
	}

	return nil
}

// GetAppliedMigrations returns the list of applied migrations.
func GetAppliedMigrations(db *sql.DB) ([]MigrationRecord, error) {
	rows, err := db.Query(`SELECT version, description, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []MigrationRecord
	for rows.Next() {
		var r MigrationRecord
		if err := rows.Scan(&r.Version, &r.Description, &r.AppliedAt); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}
