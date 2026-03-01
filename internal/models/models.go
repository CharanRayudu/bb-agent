package models

import (
	"time"

	"github.com/google/uuid"
)

// FlowStatus represents the lifecycle state of a pentest flow
type FlowStatus string

const (
	FlowStatusActive    FlowStatus = "active"
	FlowStatusCompleted FlowStatus = "completed"
	FlowStatusFailed    FlowStatus = "failed"
	FlowStatusPaused    FlowStatus = "paused"
)

// TaskStatus represents the lifecycle state of a task
type TaskStatus string

const (
	TaskStatusPending TaskStatus = "pending"
	TaskStatusRunning TaskStatus = "running"
	TaskStatusDone    TaskStatus = "done"
	TaskStatusFailed  TaskStatus = "failed"
)

// SubTaskStatus represents the lifecycle state of a subtask
type SubTaskStatus string

const (
	SubTaskStatusQueued    SubTaskStatus = "queued"
	SubTaskStatusRunning   SubTaskStatus = "running"
	SubTaskStatusCompleted SubTaskStatus = "completed"
	SubTaskStatusFailed    SubTaskStatus = "failed"
)

// AgentType represents which specialist agent handles a subtask
type AgentType string

const (
	AgentTypeOrchestrator AgentType = "orchestrator"
	AgentTypeResearcher   AgentType = "researcher"
	AgentTypeExecutor     AgentType = "executor"
	AgentTypeReporter     AgentType = "reporter"
)

// ActionType represents what kind of action was performed
type ActionType string

const (
	ActionTypeCommand ActionType = "command"
	ActionTypeSearch  ActionType = "search"
	ActionTypeAnalyze ActionType = "analyze"
	ActionTypeLLMCall ActionType = "llm_call"
	ActionTypeReport  ActionType = "report"
)

// Flow represents a top-level penetration testing engagement
type Flow struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description" db:"description"`
	Target      string     `json:"target" db:"target"`
	Status      FlowStatus `json:"status" db:"status"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	Tasks       []Task     `json:"tasks,omitempty"`
}

// Task represents a major step in the pentest flow
type Task struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	FlowID      uuid.UUID  `json:"flow_id" db:"flow_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description" db:"description"`
	Status      TaskStatus `json:"status" db:"status"`
	Result      string     `json:"result" db:"result"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	SubTasks    []SubTask  `json:"subtasks,omitempty"`
}

// SubTask represents a delegated piece of work assigned to a specialist agent
type SubTask struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	TaskID      uuid.UUID     `json:"task_id" db:"task_id"`
	Name        string        `json:"name" db:"name"`
	Description string        `json:"description" db:"description"`
	Status      SubTaskStatus `json:"status" db:"status"`
	AgentType   AgentType     `json:"agent_type" db:"agent_type"`
	Context     string        `json:"context" db:"context"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
	Actions     []Action      `json:"actions,omitempty"`
}

// Action represents a single operation performed during a subtask
type Action struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	SubTaskID uuid.UUID  `json:"subtask_id" db:"subtask_id"`
	Type      ActionType `json:"type" db:"type"`
	Input     string     `json:"input" db:"input"`
	Output    string     `json:"output" db:"output"`
	Status    string     `json:"status" db:"status"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// Artifact represents a file or report produced during testing
type Artifact struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ActionID  uuid.UUID `json:"action_id" db:"action_id"`
	FlowID    uuid.UUID `json:"flow_id" db:"flow_id"`
	Type      string    `json:"type" db:"type"`
	Name      string    `json:"name" db:"name"`
	Content   string    `json:"content" db:"content"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Memory represents a vector-stored observation for long-term recall
type Memory struct {
	ID        uuid.UUID `json:"id" db:"id"`
	FlowID    uuid.UUID `json:"flow_id" db:"flow_id"`
	ActionID  uuid.UUID `json:"action_id" db:"action_id"`
	Type      string    `json:"type" db:"type"`
	Content   string    `json:"content" db:"content"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// Embedding is stored in pgvector, not loaded into Go struct
}

// ChatMessage represents a message in the agent's conversation chain
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall represents an LLM tool/function call
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolResult represents the result of executing a tool
type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
}
