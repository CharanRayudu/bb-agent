package agent

import (
	"fmt"
	"sync"
	"time"
)

// AuditEvent captures a single actor action on a resource.
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`    // username or "anonymous"
	Action    string                 `json:"action"`   // e.g. "scan_started"
	Resource  string                 `json:"resource"` // flow ID, finding ID, etc.
	Details   map[string]interface{} `json:"details,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty"`
}

// AuditLog is an in-memory append-only event log.
type AuditLog struct {
	events []AuditEvent
	mu     sync.RWMutex
	seq    uint64
}

// NewAuditLog creates an empty audit log.
func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

// Record appends a new event to the log.
func (l *AuditLog) Record(actor, action, resource string, details map[string]interface{}, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e := AuditEvent{
		ID:        fmt.Sprintf("audit-%d", l.seq),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: ip,
	}
	l.events = append(l.events, e)
}

// GetAll returns a snapshot of all audit events.
func (l *AuditLog) GetAll() []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]AuditEvent, len(l.events))
	copy(out, l.events)
	return out
}

// GetByActor returns all audit events for the given actor.
func (l *AuditLog) GetByActor(actor string) []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var out []AuditEvent
	for _, e := range l.events {
		if e.Actor == actor {
			out = append(out, e)
		}
	}
	return out
}
