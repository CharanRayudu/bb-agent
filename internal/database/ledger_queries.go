package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

// SubTaskCreateOptions captures the richer execution metadata used by the task ledger.
type SubTaskCreateOptions struct {
	ParentSubTaskID *uuid.UUID
	Context         string
	Kind            models.SubTaskKind
	QueueName       string
	Target          string
	Priority        string
	Fingerprint     string
	Result          string
	Outcome         models.SubTaskOutcome
	Metadata        map[string]any
}

func marshalJSONMap(data map[string]any) []byte {
	if len(data) == 0 {
		return []byte("{}")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func scanSubTask(
	scan func(dest ...any) error,
	st *models.SubTask,
) error {
	var parentID sql.NullString
	var metadataJSON []byte
	if err := scan(
		&st.ID,
		&st.TaskID,
		&parentID,
		&st.Name,
		&st.Description,
		&st.Status,
		&st.AgentType,
		&st.Context,
		&st.Kind,
		&st.QueueName,
		&st.Target,
		&st.Priority,
		&st.Fingerprint,
		&st.Result,
		&st.Outcome,
		&metadataJSON,
		&st.CreatedAt,
		&st.UpdatedAt,
	); err != nil {
		return err
	}

	if parentID.Valid {
		if parsed, err := uuid.Parse(parentID.String); err == nil {
			st.ParentSubTaskID = &parsed
		}
	}

	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &st.Metadata)
	}
	if st.Metadata == nil {
		st.Metadata = map[string]any{}
	}

	return nil
}

// CreateSubTaskWithOptions creates a subtask enriched with scheduling metadata.
func (q *Queries) CreateSubTaskWithOptions(
	taskID uuid.UUID,
	name string,
	description string,
	agentType models.AgentType,
	opts SubTaskCreateOptions,
) (*models.SubTask, error) {
	st := &models.SubTask{
		ID:              uuid.New(),
		TaskID:          taskID,
		ParentSubTaskID: opts.ParentSubTaskID,
		Name:            name,
		Description:     description,
		Status:          models.SubTaskStatusQueued,
		AgentType:       agentType,
		Context:         opts.Context,
		Kind:            opts.Kind,
		QueueName:       opts.QueueName,
		Target:          opts.Target,
		Priority:        opts.Priority,
		Fingerprint:     opts.Fingerprint,
		Result:          opts.Result,
		Outcome:         opts.Outcome,
		Metadata:        opts.Metadata,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if st.Kind == "" {
		st.Kind = models.SubTaskKindPhase
	}
	if st.Priority == "" {
		st.Priority = "medium"
	}
	if st.Outcome == "" {
		st.Outcome = models.SubTaskOutcomePending
	}
	if st.Metadata == nil {
		st.Metadata = map[string]any{}
	}

	_, err := q.db.Exec(
		`INSERT INTO subtasks (
			id, task_id, parent_subtask_id, name, description, status, agent_type, context,
			kind, queue_name, target, priority, fingerprint, result, outcome, metadata,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18
		)`,
		st.ID,
		st.TaskID,
		st.ParentSubTaskID,
		st.Name,
		st.Description,
		st.Status,
		st.AgentType,
		st.Context,
		st.Kind,
		st.QueueName,
		st.Target,
		st.Priority,
		st.Fingerprint,
		st.Result,
		st.Outcome,
		marshalJSONMap(st.Metadata),
		st.CreatedAt,
		st.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create subtask: %w", err)
	}
	return st, nil
}

// UpdateSubTaskState updates lifecycle status, result summary, and execution outcome.
func (q *Queries) UpdateSubTaskState(
	id uuid.UUID,
	status models.SubTaskStatus,
	result string,
	outcome models.SubTaskOutcome,
	metadata map[string]any,
) error {
	_, err := q.db.Exec(
		`UPDATE subtasks
		 SET status = $1,
		     result = $2,
		     outcome = $3,
		     metadata = $4,
		     updated_at = NOW()
		 WHERE id = $5`,
		status,
		result,
		outcome,
		marshalJSONMap(metadata),
		id,
	)
	return err
}

// GetTaskLedgerByFlow returns tasks with their enriched subtasks attached.
func (q *Queries) GetTaskLedgerByFlow(flowID uuid.UUID) ([]models.Task, error) {
	tasks, err := q.GetTasksByFlow(flowID)
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return tasks, nil
	}

	rows, err := q.db.Query(
		`SELECT
			s.id, s.task_id, s.parent_subtask_id, s.name, s.description, s.status, s.agent_type, s.context,
			s.kind, s.queue_name, s.target, s.priority, s.fingerprint, s.result, s.outcome, s.metadata,
			s.created_at, s.updated_at
		 FROM subtasks s
		 JOIN tasks t ON t.id = s.task_id
		 WHERE t.flow_id = $1
		 ORDER BY s.created_at ASC`,
		flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	taskIndex := make(map[uuid.UUID]int, len(tasks))
	for i := range tasks {
		taskIndex[tasks[i].ID] = i
		tasks[i].SubTasks = []models.SubTask{}
	}

	for rows.Next() {
		var st models.SubTask
		if err := scanSubTask(rows.Scan, &st); err != nil {
			return nil, err
		}
		idx, ok := taskIndex[st.TaskID]
		if !ok {
			continue
		}
		tasks[idx].SubTasks = append(tasks[idx].SubTasks, st)
	}

	return tasks, rows.Err()
}

func scanEvidencePack(scan func(dest ...any) error, pack *models.EvidencePack) error {
	var proofJSON []byte
	var taskID sql.NullString
	var subTaskID sql.NullString
	if err := scan(
		&pack.ID,
		&pack.FlowID,
		&taskID,
		&subTaskID,
		&pack.Fingerprint,
		&pack.Status,
		&pack.Type,
		&pack.URL,
		&pack.Parameter,
		&pack.Payload,
		&pack.Severity,
		&pack.Confidence,
		&pack.Summary,
		&pack.SourceAgent,
		&proofJSON,
		&pack.CreatedAt,
		&pack.UpdatedAt,
	); err != nil {
		return err
	}

	if taskID.Valid {
		if parsed, err := uuid.Parse(taskID.String); err == nil {
			pack.TaskID = &parsed
		}
	}
	if subTaskID.Valid {
		if parsed, err := uuid.Parse(subTaskID.String); err == nil {
			pack.SubTaskID = &parsed
		}
	}
	if len(proofJSON) > 0 {
		_ = json.Unmarshal(proofJSON, &pack.Proof)
	}
	if pack.Proof == nil {
		pack.Proof = map[string]any{}
	}

	return nil
}

// UpsertEvidencePack stores or updates proof for a hypothesis/finding.
func (q *Queries) UpsertEvidencePack(pack *models.EvidencePack) error {
	if pack == nil {
		return nil
	}
	if pack.ID == uuid.Nil {
		pack.ID = uuid.New()
	}
	if pack.CreatedAt.IsZero() {
		pack.CreatedAt = time.Now()
	}
	pack.UpdatedAt = time.Now()

	row := q.db.QueryRow(
		`INSERT INTO evidence_packs (
			id, flow_id, task_id, subtask_id, fingerprint, status, finding_type, target_url,
			parameter, payload, severity, confidence, summary, source_agent, proof,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15,
			$16, $17
		)
		ON CONFLICT (flow_id, fingerprint) DO UPDATE SET
			task_id = COALESCE(EXCLUDED.task_id, evidence_packs.task_id),
			subtask_id = COALESCE(EXCLUDED.subtask_id, evidence_packs.subtask_id),
			status = EXCLUDED.status,
			finding_type = EXCLUDED.finding_type,
			target_url = EXCLUDED.target_url,
			parameter = EXCLUDED.parameter,
			payload = EXCLUDED.payload,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			summary = EXCLUDED.summary,
			source_agent = EXCLUDED.source_agent,
			proof = EXCLUDED.proof,
			updated_at = EXCLUDED.updated_at
		RETURNING id, created_at, updated_at`,
		pack.ID,
		pack.FlowID,
		pack.TaskID,
		pack.SubTaskID,
		pack.Fingerprint,
		pack.Status,
		pack.Type,
		pack.URL,
		pack.Parameter,
		pack.Payload,
		pack.Severity,
		pack.Confidence,
		pack.Summary,
		pack.SourceAgent,
		marshalJSONMap(pack.Proof),
		pack.CreatedAt,
		pack.UpdatedAt,
	)

	return row.Scan(&pack.ID, &pack.CreatedAt, &pack.UpdatedAt)
}

// GetEvidencePacksByFlow returns all evidence packs for a flow.
func (q *Queries) GetEvidencePacksByFlow(flowID uuid.UUID) ([]models.EvidencePack, error) {
	rows, err := q.db.Query(
		`SELECT
			id, flow_id, task_id, subtask_id, fingerprint, status, finding_type, target_url,
			parameter, payload, severity, confidence, summary, source_agent, proof,
			created_at, updated_at
		 FROM evidence_packs
		 WHERE flow_id = $1
		 ORDER BY updated_at DESC, created_at DESC`,
		flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packs []models.EvidencePack
	for rows.Next() {
		var pack models.EvidencePack
		if err := scanEvidencePack(rows.Scan, &pack); err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	return packs, rows.Err()
}

// GetFlowLedger builds the authoritative execution ledger for a flow.
func (q *Queries) GetFlowLedger(flowID uuid.UUID) (*models.FlowLedger, error) {
	tasks, err := q.GetTaskLedgerByFlow(flowID)
	if err != nil {
		return nil, err
	}
	evidence, err := q.GetEvidencePacksByFlow(flowID)
	if err != nil {
		return nil, err
	}
	snapshot, err := q.GetLatestBrainSnapshot(flowID)
	if err != nil {
		return nil, err
	}

	ledger := &models.FlowLedger{
		FlowID:   flowID,
		Tasks:    tasks,
		Evidence: evidence,
		Snapshot: snapshot,
		Summary: models.FlowLedgerSummary{
			TotalTasks: len(tasks),
		},
	}

	for _, task := range tasks {
		for _, subtask := range task.SubTasks {
			ledger.Summary.TotalSubTasks++
			switch subtask.Status {
			case models.SubTaskStatusRunning:
				ledger.Summary.RunningSubTasks++
			case models.SubTaskStatusCompleted:
				ledger.Summary.CompletedSubTasks++
			}
		}
	}

	for _, pack := range evidence {
		switch pack.Status {
		case models.EvidenceStatusConfirmed:
			ledger.Summary.ConfirmedEvidence++
		case models.EvidenceStatusNeedsProof, models.EvidenceStatusHypothesis:
			ledger.Summary.NeedsProof++
		case models.EvidenceStatusRejected:
			ledger.Summary.RejectedEvidence++
		}
	}

	return ledger, nil
}
