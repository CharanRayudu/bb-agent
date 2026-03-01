package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// Connect establishes a connection to PostgreSQL
func Connect(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	log.Println("✅ Connected to PostgreSQL")
	return db, nil
}

// RunMigrations creates the schema if it doesn't exist
func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,
		`CREATE EXTENSION IF NOT EXISTS "vector"`,

		`CREATE TABLE IF NOT EXISTS flows (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS tasks (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			result TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS subtasks (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'queued',
			agent_type TEXT NOT NULL DEFAULT 'orchestrator',
			context TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS actions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			subtask_id UUID NOT NULL REFERENCES subtasks(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			input TEXT NOT NULL DEFAULT '',
			output TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'success',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS artifacts (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			action_id UUID REFERENCES actions(id) ON DELETE SET NULL,
			flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
			type TEXT NOT NULL DEFAULT 'report',
			name TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS memories (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
			action_id UUID REFERENCES actions(id) ON DELETE SET NULL,
			type TEXT NOT NULL DEFAULT 'observation',
			content TEXT NOT NULL,
			embedding vector(1536),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS flow_events (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			metadata JSONB NOT NULL DEFAULT '{}',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE INDEX IF NOT EXISTS idx_tasks_flow_id ON tasks(flow_id)`,
		`CREATE INDEX IF NOT EXISTS idx_subtasks_task_id ON subtasks(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_actions_subtask_id ON actions(subtask_id)`,
		`CREATE INDEX IF NOT EXISTS idx_memories_flow_id ON memories(flow_id)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_events_flow_id ON flow_events(flow_id)`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %s\nerror: %w", m[:min(len(m), 80)], err)
		}
	}

	log.Println("✅ Database migrations complete")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
