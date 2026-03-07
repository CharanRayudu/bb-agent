package models

import (
	"time"

	"github.com/google/uuid"
)

// SubTaskKind classifies a unit of execution in the scan ledger.
type SubTaskKind string

const (
	SubTaskKindPhase        SubTaskKind = "phase"
	SubTaskKindSpecialist   SubTaskKind = "specialist"
	SubTaskKindValidation   SubTaskKind = "validation"
	SubTaskKindReporting    SubTaskKind = "reporting"
	SubTaskKindPivot        SubTaskKind = "pivot"
	SubTaskKindPostExploit  SubTaskKind = "post_exploit"
	SubTaskKindReconSupport SubTaskKind = "recon_support"
)

// SubTaskOutcome captures the terminal execution result for a subtask.
type SubTaskOutcome string

const (
	SubTaskOutcomePending          SubTaskOutcome = "pending"
	SubTaskOutcomeRunning          SubTaskOutcome = "running"
	SubTaskOutcomeCompleted        SubTaskOutcome = "completed"
	SubTaskOutcomeConfirmed        SubTaskOutcome = "confirmed"
	SubTaskOutcomeRejected         SubTaskOutcome = "rejected"
	SubTaskOutcomeNeedsProof       SubTaskOutcome = "needs_proof"
	SubTaskOutcomeBlockedByScope   SubTaskOutcome = "blocked_by_scope"
	SubTaskOutcomeBlockedByRuntime SubTaskOutcome = "blocked_by_runtime"
	SubTaskOutcomeExhausted        SubTaskOutcome = "exhausted"
	SubTaskOutcomeNeedsHuman       SubTaskOutcome = "needs_human"
)

// EvidenceStatus models how far a hypothesis has progressed.
type EvidenceStatus string

const (
	EvidenceStatusHypothesis EvidenceStatus = "hypothesis"
	EvidenceStatusNeedsProof EvidenceStatus = "needs_proof"
	EvidenceStatusConfirmed  EvidenceStatus = "confirmed"
	EvidenceStatusRejected   EvidenceStatus = "rejected"
)

// EvidencePack stores proof or rejection data for a hypothesis or finding.
type EvidencePack struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	FlowID      uuid.UUID      `json:"flow_id" db:"flow_id"`
	TaskID      *uuid.UUID     `json:"task_id,omitempty" db:"task_id"`
	SubTaskID   *uuid.UUID     `json:"subtask_id,omitempty" db:"subtask_id"`
	Fingerprint string         `json:"fingerprint" db:"fingerprint"`
	Status      EvidenceStatus `json:"status" db:"status"`
	Type        string         `json:"type" db:"finding_type"`
	URL         string         `json:"url" db:"target_url"`
	Parameter   string         `json:"parameter" db:"parameter"`
	Payload     string         `json:"payload" db:"payload"`
	Severity    string         `json:"severity" db:"severity"`
	Confidence  float64        `json:"confidence" db:"confidence"`
	Summary     string         `json:"summary" db:"summary"`
	SourceAgent string         `json:"source_agent" db:"source_agent"`
	Proof       map[string]any `json:"proof,omitempty" db:"-"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// BrainSnapshot stores the latest durable runtime state for a flow.
type BrainSnapshot struct {
	ID        uuid.UUID      `json:"id" db:"id"`
	FlowID    uuid.UUID      `json:"flow_id" db:"flow_id"`
	TaskID    *uuid.UUID     `json:"task_id,omitempty" db:"task_id"`
	Stage     string         `json:"stage" db:"stage"`
	Revision  int            `json:"revision" db:"revision"`
	State     map[string]any `json:"state" db:"-"`
	Summary   map[string]any `json:"summary" db:"-"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" db:"updated_at"`
}

// FlowLedgerSummary provides roll-up metrics for the execution ledger.
type FlowLedgerSummary struct {
	TotalTasks        int `json:"total_tasks"`
	TotalSubTasks     int `json:"total_subtasks"`
	RunningSubTasks   int `json:"running_subtasks"`
	CompletedSubTasks int `json:"completed_subtasks"`
	ConfirmedEvidence int `json:"confirmed_evidence"`
	NeedsProof        int `json:"needs_proof"`
	RejectedEvidence  int `json:"rejected_evidence"`
}

// FlowLedger is the API shape for the authoritative execution ledger.
type FlowLedger struct {
	FlowID   uuid.UUID         `json:"flow_id"`
	Tasks    []Task            `json:"tasks"`
	Evidence []EvidencePack    `json:"evidence"`
	Snapshot *BrainSnapshot    `json:"snapshot,omitempty"`
	Summary  FlowLedgerSummary `json:"summary"`
}
