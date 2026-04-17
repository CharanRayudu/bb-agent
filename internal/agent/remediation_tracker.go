package agent

import (
	"fmt"
	"sync"
	"time"
)

// RemediationStatus represents the lifecycle state of a finding's remediation.
type RemediationStatus string

const (
	StatusOpen        RemediationStatus = "open"
	StatusInProgress  RemediationStatus = "in_progress"
	StatusFixed       RemediationStatus = "fixed"
	StatusWontFix     RemediationStatus = "wont_fix"
	StatusReopened    RemediationStatus = "reopened"
)

// RemediationRecord tracks the remediation lifecycle for a single finding.
type RemediationRecord struct {
	FindingID  string            `json:"finding_id"`
	Status     RemediationStatus `json:"status"`
	AssignedTo string            `json:"assigned_to"`
	Notes      string            `json:"notes"`
	VerifiedAt *time.Time        `json:"verified_at,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// RemediationTracker manages remediation records for findings.
type RemediationTracker struct {
	records map[string]*RemediationRecord
	mu      sync.RWMutex
}

// NewRemediationTracker creates an empty tracker.
func NewRemediationTracker() *RemediationTracker {
	return &RemediationTracker{
		records: make(map[string]*RemediationRecord),
	}
}

// UpdateStatus creates or updates the remediation record for the given finding.
func (t *RemediationTracker) UpdateStatus(findingID string, status RemediationStatus, operator, notes string) error {
	if findingID == "" {
		return fmt.Errorf("findingID is required")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	rec, exists := t.records[findingID]
	if !exists {
		rec = &RemediationRecord{
			FindingID: findingID,
			CreatedAt: now,
		}
		t.records[findingID] = rec
	}

	rec.Status = status
	rec.UpdatedAt = now
	if operator != "" {
		rec.AssignedTo = operator
	}
	if notes != "" {
		rec.Notes = notes
	}

	return nil
}

// GetStatus returns the current remediation status for a finding, defaulting to open.
func (t *RemediationTracker) GetStatus(findingID string) RemediationStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rec, ok := t.records[findingID]
	if !ok {
		return StatusOpen
	}
	return rec.Status
}

// GetAll returns a snapshot of all remediation records.
func (t *RemediationTracker) GetAll() []*RemediationRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]*RemediationRecord, 0, len(t.records))
	for _, r := range t.records {
		cp := *r
		out = append(out, &cp)
	}
	return out
}

// MarkVerified stamps a verified timestamp on the record.
func (t *RemediationTracker) MarkVerified(findingID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, ok := t.records[findingID]
	if !ok {
		return fmt.Errorf("no remediation record for finding %s", findingID)
	}

	now := time.Now()
	rec.VerifiedAt = &now
	rec.UpdatedAt = now
	return nil
}
