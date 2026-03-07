package database

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

func scanBrainSnapshot(scan func(dest ...any) error, snapshot *models.BrainSnapshot) error {
	var taskID sql.NullString
	var stateJSON []byte
	var summaryJSON []byte

	if err := scan(
		&snapshot.ID,
		&snapshot.FlowID,
		&taskID,
		&snapshot.Stage,
		&snapshot.Revision,
		&stateJSON,
		&summaryJSON,
		&snapshot.CreatedAt,
		&snapshot.UpdatedAt,
	); err != nil {
		return err
	}

	if taskID.Valid {
		if parsed, err := uuid.Parse(taskID.String); err == nil {
			snapshot.TaskID = &parsed
		}
	}
	if len(stateJSON) > 0 {
		_ = json.Unmarshal(stateJSON, &snapshot.State)
	}
	if snapshot.State == nil {
		snapshot.State = map[string]any{}
	}
	if len(summaryJSON) > 0 {
		_ = json.Unmarshal(summaryJSON, &snapshot.Summary)
	}
	if snapshot.Summary == nil {
		snapshot.Summary = map[string]any{}
	}

	return nil
}

// UpsertBrainSnapshot stores the latest durable runtime state for a flow.
func (q *Queries) UpsertBrainSnapshot(snapshot *models.BrainSnapshot) error {
	if snapshot == nil {
		return nil
	}
	if snapshot.ID == uuid.Nil {
		snapshot.ID = uuid.New()
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now()
	}
	if snapshot.Revision <= 0 {
		snapshot.Revision = 1
	}
	if snapshot.Stage == "" {
		snapshot.Stage = "runtime"
	}
	if snapshot.State == nil {
		snapshot.State = map[string]any{}
	}
	if snapshot.Summary == nil {
		snapshot.Summary = map[string]any{}
	}
	snapshot.UpdatedAt = time.Now()

	row := q.db.QueryRow(
		`INSERT INTO brain_snapshots (
			id, flow_id, task_id, stage, revision, state, summary, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (flow_id) DO UPDATE SET
			task_id = COALESCE(EXCLUDED.task_id, brain_snapshots.task_id),
			stage = EXCLUDED.stage,
			revision = brain_snapshots.revision + 1,
			state = EXCLUDED.state,
			summary = EXCLUDED.summary,
			updated_at = EXCLUDED.updated_at
		RETURNING id, revision, created_at, updated_at`,
		snapshot.ID,
		snapshot.FlowID,
		snapshot.TaskID,
		snapshot.Stage,
		snapshot.Revision,
		marshalJSONMap(snapshot.State),
		marshalJSONMap(snapshot.Summary),
		snapshot.CreatedAt,
		snapshot.UpdatedAt,
	)

	return row.Scan(&snapshot.ID, &snapshot.Revision, &snapshot.CreatedAt, &snapshot.UpdatedAt)
}

// GetLatestBrainSnapshot loads the latest durable runtime state for a flow.
func (q *Queries) GetLatestBrainSnapshot(flowID uuid.UUID) (*models.BrainSnapshot, error) {
	row := q.db.QueryRow(
		`SELECT
			id, flow_id, task_id, stage, revision, state, summary, created_at, updated_at
		 FROM brain_snapshots
		 WHERE flow_id = $1
		 ORDER BY updated_at DESC
		 LIMIT 1`,
		flowID,
	)

	snapshot := &models.BrainSnapshot{}
	if err := scanBrainSnapshot(row.Scan, snapshot); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return snapshot, nil
}
