package agent

import (
	"context"
	"sync"
)

// APTSApprovalGate is a flow-scoped channel used at L2 to pause before exploitation
// until a human approves via POST /api/flows/{id}/approve-exploitation.
type APTSApprovalGate struct {
	ch     chan struct{}
	once   sync.Once
	denied bool
	mu     sync.Mutex
}

// NewAPTSApprovalGate creates a new approval gate.
func NewAPTSApprovalGate() *APTSApprovalGate {
	return &APTSApprovalGate{ch: make(chan struct{})}
}

// Wait blocks until the gate is opened or ctx is cancelled. Returns true if approved.
func (g *APTSApprovalGate) Wait(ctx context.Context) bool {
	select {
	case <-g.ch:
		g.mu.Lock()
		defer g.mu.Unlock()
		return !g.denied
	case <-ctx.Done():
		return false
	}
}

// Approve opens the gate (exploitation is permitted).
func (g *APTSApprovalGate) Approve() {
	g.once.Do(func() { close(g.ch) })
}

// Deny opens the gate with a rejection (exploitation is blocked).
func (g *APTSApprovalGate) Deny() {
	g.mu.Lock()
	g.denied = true
	g.mu.Unlock()
	g.once.Do(func() { close(g.ch) })
}

// AutonomyLevel defines how much human oversight is required per OWASP APTS Domain 4.
// Levels are cumulative: each level includes all controls from lower levels.
type AutonomyLevel string

const (
	// AutonomyL1 (Assisted): AI recommends actions, human approves each one.
	// Exploitation, lateral movement, data access all require explicit approval.
	AutonomyL1 AutonomyLevel = "L1"

	// AutonomyL2 (Supervised): AI executes recon autonomously.
	// Exploitation and data exfiltration require human approval before proceeding.
	AutonomyL2 AutonomyLevel = "L2"

	// AutonomyL3 (Autonomous): AI operates end-to-end within approved scope.
	// This is the default level for most engagements.
	AutonomyL3 AutonomyLevel = "L3"

	// AutonomyL4 (Critical Infrastructure): Highest assurance level.
	// Full audit trail, continuous monitoring, quarterly containment verification.
	AutonomyL4 AutonomyLevel = "L4"

	// AutonomyDefault is the level used when none is specified.
	AutonomyDefault = AutonomyL3
)

// String returns the string representation of the autonomy level.
func (a AutonomyLevel) String() string { return string(a) }

// ParseAutonomyLevel converts a string to an AutonomyLevel, defaulting to L3.
func ParseAutonomyLevel(s string) AutonomyLevel {
	switch s {
	case "L1", "l1", "assisted":
		return AutonomyL1
	case "L2", "l2", "supervised":
		return AutonomyL2
	case "L4", "l4", "critical":
		return AutonomyL4
	default:
		return AutonomyL3
	}
}

// APTSAutonomyPolicy describes the operational constraints for a given autonomy level.
type APTSAutonomyPolicy struct {
	Level                  AutonomyLevel
	RequiresHumanApproval  []string // Phase names that need human approval
	MaxLoopIterations      int      // Maximum recon→exploit iterations
	ExploitationAllowed    bool     // Whether exploitation phase runs automatically
	AuditFrequency         string   // How often audit events are emitted
	ContainmentVerification string  // "quarterly", "monthly", or "continuous"
}

// GetAutonomyPolicy returns the operational policy for a given autonomy level.
func GetAutonomyPolicy(level AutonomyLevel) APTSAutonomyPolicy {
	switch level {
	case AutonomyL1:
		return APTSAutonomyPolicy{
			Level:                  AutonomyL1,
			RequiresHumanApproval:  []string{"recon", "strategy", "exploitation", "validation"},
			MaxLoopIterations:      1,
			ExploitationAllowed:    false,
			AuditFrequency:         "every_action",
			ContainmentVerification: "continuous",
		}
	case AutonomyL2:
		return APTSAutonomyPolicy{
			Level:                  AutonomyL2,
			RequiresHumanApproval:  []string{"exploitation", "validation"},
			MaxLoopIterations:      2,
			ExploitationAllowed:    false, // Requires approval gate
			AuditFrequency:         "every_phase",
			ContainmentVerification: "monthly",
		}
	case AutonomyL4:
		return APTSAutonomyPolicy{
			Level:                  AutonomyL4,
			RequiresHumanApproval:  []string{},
			MaxLoopIterations:      5,
			ExploitationAllowed:    true,
			AuditFrequency:         "every_action",
			ContainmentVerification: "monthly",
		}
	default: // L3
		return APTSAutonomyPolicy{
			Level:                  AutonomyL3,
			RequiresHumanApproval:  []string{},
			MaxLoopIterations:      3,
			ExploitationAllowed:    true,
			AuditFrequency:         "every_phase",
			ContainmentVerification: "quarterly",
		}
	}
}

// PhaseRequiresApproval returns true if the given pipeline phase requires human
// approval before proceeding at this autonomy level.
func (p APTSAutonomyPolicy) PhaseRequiresApproval(phase string) bool {
	for _, r := range p.RequiresHumanApproval {
		if r == phase {
			return true
		}
	}
	return false
}
