package pipeline

import (
	"fmt"
	"sync"
	"time"
)

// Transition records a single phase change for debugging and metrics.
type Transition struct {
	From      Phase
	To        Phase
	Reason    string
	Timestamp time.Time
	Duration  time.Duration // How long we spent in the "From" phase
	Metrics   map[string]interface{}
}

// State is the pipeline state machine.
// It tracks the current phase, transition history, and timing.
// Thread-safe via sync.RWMutex.
type State struct {
	mu sync.RWMutex

	ScanID       string
	CurrentPhase Phase
	PausedFrom   Phase // The phase we were in before pausing

	// Timing
	StartedAt      time.Time
	PhaseStartedAt time.Time

	// History
	Transitions []Transition

	// Phase metrics (items processed, findings, etc.)
	PhaseMetrics map[Phase]map[string]interface{}
}

// NewState creates a new pipeline state for the given scan.
func NewState(scanID string) *State {
	return &State{
		ScanID:       scanID,
		CurrentPhase: PhaseIdle,
		PhaseMetrics: make(map[Phase]map[string]interface{}),
		Transitions:  make([]Transition, 0, 10),
	}
}

// Current returns the current phase (thread-safe read).
func (s *State) Current() Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentPhase
}

// Transition transitions the pipeline to a new phase.
// Returns an error if the transition is invalid.
func (s *State) Transition(to Phase, reason string, metrics map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	from := s.CurrentPhase

	if !CanTransition(from, to) {
		return fmt.Errorf("invalid transition: %s -> %s", from, to)
	}

	now := time.Now()

	// Calculate how long we spent in the current phase
	var duration time.Duration
	if !s.PhaseStartedAt.IsZero() {
		duration = now.Sub(s.PhaseStartedAt)
	}

	// Record the transition
	t := Transition{
		From:      from,
		To:        to,
		Reason:    reason,
		Timestamp: now,
		Duration:  duration,
		Metrics:   metrics,
	}
	s.Transitions = append(s.Transitions, t)

	// Store metrics for the phase we're leaving
	if metrics != nil {
		s.PhaseMetrics[from] = metrics
	}

	// Handle special transitions
	if to == PhasePaused {
		s.PausedFrom = from
	}

	// Update state
	s.CurrentPhase = to
	s.PhaseStartedAt = now

	// Track pipeline start time
	if from == PhaseIdle && to == PhaseReconnaissance {
		s.StartedAt = now
	}

	return nil
}

// Start transitions the pipeline from IDLE to RECONNAISSANCE.
func (s *State) Start() error {
	return s.Transition(PhaseReconnaissance, "Pipeline started", nil)
}

// Advance transitions to the next sequential phase.
// Returns an error if the pipeline is not in an active sequential phase.
func (s *State) Advance(reason string, metrics map[string]interface{}) error {
	s.mu.RLock()
	current := s.CurrentPhase
	s.mu.RUnlock()

	next, ok := nextPhase[current]
	if !ok {
		return fmt.Errorf("cannot advance from %s: not a sequential phase", current)
	}
	return s.Transition(next, reason, metrics)
}

// nextPhase maps each active phase to its natural successor.
var nextPhase = map[Phase]Phase{
	PhaseReconnaissance: PhaseDiscovery,
	PhaseDiscovery:      PhaseStrategy,
	PhaseStrategy:       PhaseExploitation,
	PhaseExploitation:   PhaseValidation,
	PhaseValidation:     PhaseReporting,
	PhaseReporting:      PhaseComplete,
}

// Pause pauses the pipeline at the current phase boundary.
func (s *State) Pause(reason string) error {
	return s.Transition(PhasePaused, reason, nil)
}

// Resume resumes the pipeline from PAUSED back to the phase it was in.
func (s *State) Resume() error {
	s.mu.RLock()
	resumeTo := s.PausedFrom
	s.mu.RUnlock()

	if resumeTo == PhaseIdle || resumeTo == PhaseComplete || resumeTo == PhaseError {
		return fmt.Errorf("cannot resume to %s", resumeTo)
	}
	return s.Transition(resumeTo, "Pipeline resumed", nil)
}

// Fail transitions the pipeline to ERROR.
func (s *State) Fail(reason string) error {
	return s.Transition(PhaseError, reason, nil)
}

// Reset transitions the pipeline back to IDLE.
func (s *State) Reset() error {
	return s.Transition(PhaseIdle, "Pipeline reset", nil)
}

// ResetToRecon forcefully transitions the pipeline back to RECONNAISSANCE.
// This is used for Iterative Feedback Loops when new credentials/access is discovered.
func (s *State) ResetToRecon(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	from := s.CurrentPhase
	to := PhaseReconnaissance
	now := time.Now()

	var duration time.Duration
	if !s.PhaseStartedAt.IsZero() {
		duration = now.Sub(s.PhaseStartedAt)
	}

	t := Transition{
		From:      from,
		To:        to,
		Reason:    reason,
		Timestamp: now,
		Duration:  duration,
		Metrics:   map[string]interface{}{"loop_triggered": true},
	}
	s.Transitions = append(s.Transitions, t)

	s.CurrentPhase = to
	s.PhaseStartedAt = now

	return nil
}

// TotalDuration returns how long the pipeline has been running.
func (s *State) TotalDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.StartedAt.IsZero() {
		return 0
	}
	if s.CurrentPhase.IsTerminal() {
		// Use the last transition timestamp as the end time
		if len(s.Transitions) > 0 {
			return s.Transitions[len(s.Transitions)-1].Timestamp.Sub(s.StartedAt)
		}
	}
	return time.Since(s.StartedAt)
}

// PhaseDuration returns how long the current phase has been active.
func (s *State) PhaseDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.PhaseStartedAt.IsZero() {
		return 0
	}
	return time.Since(s.PhaseStartedAt)
}

// ToMap returns a JSON-serializable representation of the pipeline state.
func (s *State) ToMap() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	transitions := make([]map[string]interface{}, len(s.Transitions))
	for i, t := range s.Transitions {
		transitions[i] = map[string]interface{}{
			"from":     t.From.String(),
			"to":       t.To.String(),
			"reason":   t.Reason,
			"time":     t.Timestamp.Format(time.RFC3339),
			"duration": t.Duration.Seconds(),
		}
	}

	return map[string]interface{}{
		"scan_id":        s.ScanID,
		"current_phase":  s.CurrentPhase.String(),
		"total_duration": s.TotalDuration().Seconds(),
		"phase_duration": s.PhaseDuration().Seconds(),
		"transitions":    transitions,
		"phase_metrics":  s.PhaseMetrics,
	}
}
