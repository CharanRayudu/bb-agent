// Package pipeline implements a 6-phase state machine for the scan pipeline.
//
// The pipeline models the following execution model:
//
//	IDLE -> RECONNAISSANCE -> DISCOVERY -> STRATEGY -> EXPLOITATION -> VALIDATION -> REPORTING -> COMPLETE
//
// Any active phase can transition to PAUSED or ERROR.
// PAUSED can resume to any active phase.
// COMPLETE and ERROR can only transition to IDLE (restart).
package pipeline

// Phase represents a pipeline execution phase.
type Phase int

const (
	PhaseIdle           Phase = iota // Not started
	PhaseReconnaissance              // GoSpider crawling, asset discovery
	PhaseDiscovery                   // DAST analysis, input classification
	PhaseStrategy                    // Thinking/Consolidation -- dedup, classify, route to queues
	PhaseExploitation                // Specialist agents working concurrently
	PhaseValidation                  // Multi-layer finding verification
	PhaseReporting                   // AI report generation
	PhaseComplete                    // Pipeline finished
	PhaseError                       // Pipeline errored
	PhasePaused                      // Pipeline paused at phase boundary
)

// String returns the human-readable name of the phase.
func (p Phase) String() string {
	switch p {
	case PhaseIdle:
		return "idle"
	case PhaseReconnaissance:
		return "reconnaissance"
	case PhaseDiscovery:
		return "discovery"
	case PhaseStrategy:
		return "strategy"
	case PhaseExploitation:
		return "exploitation"
	case PhaseValidation:
		return "validation"
	case PhaseReporting:
		return "reporting"
	case PhaseComplete:
		return "complete"
	case PhaseError:
		return "error"
	case PhasePaused:
		return "paused"
	default:
		return "unknown"
	}
}

// IsTerminal returns true if the phase is a terminal state (complete or error).
func (p Phase) IsTerminal() bool {
	return p == PhaseComplete || p == PhaseError
}

// IsActive returns true if the phase is an active scanning phase.
func (p Phase) IsActive() bool {
	return p >= PhaseReconnaissance && p <= PhaseReporting
}

// validTransitions defines the allowed phase transitions.
// Key is the current phase, value is the set of valid target phases.
var validTransitions = map[Phase]map[Phase]bool{
	PhaseIdle: {
		PhaseReconnaissance: true,
	},
	PhaseReconnaissance: {
		PhaseDiscovery: true,
		PhasePaused:    true,
		PhaseError:     true,
	},
	PhaseDiscovery: {
		PhaseStrategy: true,
		PhasePaused:   true,
		PhaseError:    true,
	},
	PhaseStrategy: {
		PhaseExploitation: true,
		PhasePaused:       true,
		PhaseError:        true,
	},
	PhaseExploitation: {
		PhaseValidation: true,
		PhasePaused:     true,
		PhaseError:      true,
	},
	PhaseValidation: {
		PhaseReporting: true,
		PhasePaused:    true,
		PhaseError:     true,
	},
	PhaseReporting: {
		PhaseComplete: true,
		PhasePaused:   true,
		PhaseError:    true,
	},
	PhaseComplete: {
		PhaseIdle: true, // Reset for new scan
	},
	PhaseError: {
		PhaseIdle: true, // Reset after error
	},
	// PAUSED can resume to any active phase
	PhasePaused: {
		PhaseReconnaissance: true,
		PhaseDiscovery:      true,
		PhaseStrategy:       true,
		PhaseExploitation:   true,
		PhaseValidation:     true,
		PhaseReporting:      true,
		PhaseError:          true,
	},
}

// CanTransition checks if a transition from the current phase to the target is valid.
func CanTransition(from, to Phase) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	return targets[to]
}
