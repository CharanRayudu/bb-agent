package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

// Queries provides data access methods
type Queries struct {
	db *sql.DB
}

func NewQueries(db *sql.DB) *Queries {
	return &Queries{db: db}
}

// ============ Flows ============

func (q *Queries) CreateFlow(name, description, target string) (*models.Flow, error) {
	flow := &models.Flow{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		Target:      target,
		Status:      models.FlowStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err := q.db.Exec(
		`INSERT INTO flows (id, name, description, target, status, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		flow.ID, flow.Name, flow.Description, flow.Target, flow.Status, flow.CreatedAt, flow.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow: %w", err)
	}
	return flow, nil
}

func (q *Queries) GetFlow(id uuid.UUID) (*models.Flow, error) {
	flow := &models.Flow{}
	err := q.db.QueryRow(
		`SELECT id, name, description, target, status, created_at, updated_at FROM flows WHERE id = $1`, id,
	).Scan(&flow.ID, &flow.Name, &flow.Description, &flow.Target, &flow.Status, &flow.CreatedAt, &flow.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get flow: %w", err)
	}
	return flow, nil
}

func (q *Queries) ListFlows() ([]models.Flow, error) {
	rows, err := q.db.Query(
		`SELECT id, name, description, target, status, created_at, updated_at FROM flows ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}
	defer rows.Close()

	var flows []models.Flow
	for rows.Next() {
		var f models.Flow
		if err := rows.Scan(&f.ID, &f.Name, &f.Description, &f.Target, &f.Status, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		flows = append(flows, f)
	}
	return flows, nil
}

func (q *Queries) UpdateFlowStatus(id uuid.UUID, status models.FlowStatus) error {
	_, err := q.db.Exec(
		`UPDATE flows SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, id,
	)
	return err
}

func (q *Queries) DeleteFlow(id uuid.UUID) error {
	_, err := q.db.Exec(`DELETE FROM flows WHERE id = $1`, id)
	return err
}

// GetHistoricalContext retrieves the compiled scratchpad memories and final reports from the most recent completed flow for a given target.
func (q *Queries) GetHistoricalContext(target string) (string, error) {
	// First, find the ID of the most recent completed flow for this exact target
	var lastFlowID uuid.UUID
	err := q.db.QueryRow(`
		SELECT id FROM flows 
		WHERE target = $1 
		ORDER BY created_at DESC 
		LIMIT 1
	`, target).Scan(&lastFlowID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No previous flow exists
		}
		return "", err
	}

	// Now fetch all reported findings and recorded memory from that specific flow
	rows, err := q.db.Query(`
		SELECT a.input, a.output
		FROM actions a
		JOIN subtasks s ON a.subtask_id = s.id
		JOIN tasks t ON s.task_id = t.id
		WHERE t.flow_id = $1 AND a.status = 'success' AND (a.type = 'report' OR a.input LIKE '%update_memory%')
		ORDER BY a.created_at ASC
	`, lastFlowID)

	if err != nil {
		return "", err
	}
	defer rows.Close()

	var compiledContext strings.Builder
	compiledContext.WriteString("PREVIOUS SCAN FINDINGS:\n")
	hasData := false

	for rows.Next() {
		var input, output string
		if err := rows.Scan(&input, &output); err == nil {
			hasData = true
			compiledContext.WriteString(fmt.Sprintf("- %s\n", output))
		}
	}

	if !hasData {
		return "", nil
	}

	return compiledContext.String(), nil
}

// ============ Tasks ============

func (q *Queries) CreateTask(flowID uuid.UUID, name, description string) (*models.Task, error) {
	task := &models.Task{
		ID:          uuid.New(),
		FlowID:      flowID,
		Name:        name,
		Description: description,
		Status:      models.TaskStatusPending,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err := q.db.Exec(
		`INSERT INTO tasks (id, flow_id, name, description, status, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		task.ID, task.FlowID, task.Name, task.Description, task.Status, task.CreatedAt, task.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}
	return task, nil
}

func (q *Queries) GetTasksByFlow(flowID uuid.UUID) ([]models.Task, error) {
	rows, err := q.db.Query(
		`SELECT id, flow_id, name, description, status, result, created_at, updated_at 
		 FROM tasks WHERE flow_id = $1 ORDER BY created_at ASC`, flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []models.Task
	for rows.Next() {
		var t models.Task
		if err := rows.Scan(&t.ID, &t.FlowID, &t.Name, &t.Description, &t.Status, &t.Result, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (q *Queries) UpdateTaskStatus(id uuid.UUID, status models.TaskStatus, result string) error {
	_, err := q.db.Exec(
		`UPDATE tasks SET status = $1, result = $2, updated_at = NOW() WHERE id = $3`,
		status, result, id,
	)
	return err
}

func (q *Queries) UpdateTasksStatusByFlow(flowID uuid.UUID, status models.TaskStatus, result string) error {
	_, err := q.db.Exec(
		`UPDATE tasks SET status = $1, result = $2, updated_at = NOW() WHERE flow_id = $3 AND (status = 'pending' OR status = 'running')`,
		status, result, flowID,
	)
	return err
}

// ============ SubTasks ============

func (q *Queries) CreateSubTask(taskID uuid.UUID, name, description string, agentType models.AgentType) (*models.SubTask, error) {
	st := &models.SubTask{
		ID:          uuid.New(),
		TaskID:      taskID,
		Name:        name,
		Description: description,
		Status:      models.SubTaskStatusQueued,
		AgentType:   agentType,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err := q.db.Exec(
		`INSERT INTO subtasks (id, task_id, name, description, status, agent_type, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		st.ID, st.TaskID, st.Name, st.Description, st.Status, st.AgentType, st.CreatedAt, st.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create subtask: %w", err)
	}
	return st, nil
}

func (q *Queries) UpdateSubTaskStatus(id uuid.UUID, status models.SubTaskStatus) error {
	_, err := q.db.Exec(
		`UPDATE subtasks SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, id,
	)
	return err
}

// ============ Actions ============

func (q *Queries) CreateAction(subtaskID uuid.UUID, actionType models.ActionType, input, output, status string) (*models.Action, error) {
	action := &models.Action{
		ID:        uuid.New(),
		SubTaskID: subtaskID,
		Type:      actionType,
		Input:     input,
		Output:    output,
		Status:    status,
		CreatedAt: time.Now(),
	}

	_, err := q.db.Exec(
		`INSERT INTO actions (id, subtask_id, type, input, output, status, created_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		action.ID, action.SubTaskID, action.Type, action.Input, action.Output, action.Status, action.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create action: %w", err)
	}
	return action, nil
}

func (q *Queries) GetActionsBySubTask(subtaskID uuid.UUID) ([]models.Action, error) {
	rows, err := q.db.Query(
		`SELECT id, subtask_id, type, input, output, status, created_at 
		 FROM actions WHERE subtask_id = $1 ORDER BY created_at ASC`, subtaskID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []models.Action
	for rows.Next() {
		var a models.Action
		if err := rows.Scan(&a.ID, &a.SubTaskID, &a.Type, &a.Input, &a.Output, &a.Status, &a.CreatedAt); err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	return actions, nil
}

func (q *Queries) GetActionsByFlow(flowID uuid.UUID) ([]models.Action, error) {
	rows, err := q.db.Query(
		`SELECT a.id, a.subtask_id, a.type, a.input, a.output, a.status, a.created_at 
		 FROM actions a
		 JOIN subtasks s ON a.subtask_id = s.id
		 JOIN tasks t ON s.task_id = t.id
		 WHERE t.flow_id = $1 
		 ORDER BY a.created_at ASC`, flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []models.Action
	for rows.Next() {
		var a models.Action
		actions = append(actions, a)
	}
	return actions, nil
}

// ============ Flow Events ============

func (q *Queries) CreateFlowEvent(flowID uuid.UUID, eventType string, content string, metadata interface{}) error {
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = q.db.Exec(
		`INSERT INTO flow_events (flow_id, type, content, metadata) 
		 VALUES ($1, $2, $3, $4)`,
		flowID, eventType, content, metaJSON,
	)
	return err
}

func (q *Queries) GetFlowEvents(flowID uuid.UUID) ([]EventWithTimestamp, error) {
	rows, err := q.db.Query(
		`SELECT type, content, metadata, timestamp FROM flow_events 
		 WHERE flow_id = $1 ORDER BY timestamp ASC`, flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EventWithTimestamp
	for rows.Next() {
		var e EventWithTimestamp
		var metaJSON []byte
		if err := rows.Scan(&e.Type, &e.Content, &metaJSON, &e.Timestamp); err != nil {
			return nil, err
		}
		json.Unmarshal(metaJSON, &e.Metadata)
		events = append(events, e)
	}
	return events, nil
}

type EventWithTimestamp struct {
	Type      string      `json:"type"`
	Content   string      `json:"content"`
	Metadata  interface{} `json:"metadata"`
	Timestamp time.Time   `json:"timestamp"`
}
