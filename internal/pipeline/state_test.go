package pipeline

import (
	"testing"
)

func TestPhaseTransitions(t *testing.T) {
	s := NewState("test-scan-1")

	// Should start at IDLE
	if s.Current() != PhaseIdle {
		t.Fatalf("expected IDLE, got %s", s.Current())
	}

	// Start the pipeline
	if err := s.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	if s.Current() != PhaseReconnaissance {
		t.Fatalf("expected RECONNAISSANCE, got %s", s.Current())
	}

	// Advance through each phase
	phases := []Phase{
		PhaseDiscovery, PhaseStrategy, PhaseExploitation,
		PhaseValidation, PhaseReporting, PhaseComplete,
	}

	for _, expectedPhase := range phases {
		if err := s.Advance("auto", nil); err != nil {
			t.Fatalf("Advance() to %s failed: %v", expectedPhase, err)
		}
		if s.Current() != expectedPhase {
			t.Fatalf("expected %s, got %s", expectedPhase, s.Current())
		}
	}

	// Should have recorded transitions
	if len(s.Transitions) < 7 {
		t.Fatalf("expected 7+ transitions, got %d", len(s.Transitions))
	}

	// Total duration should be >= 0 (pipeline completes in nanoseconds in tests)
	if s.TotalDuration() < 0 {
		t.Fatalf("expected non-negative total duration, got %v", s.TotalDuration())
	}
}

func TestInvalidTransition(t *testing.T) {
	s := NewState("test-scan-2")

	// Can't jump straight to EXPLOITATION from IDLE
	err := s.Transition(PhaseExploitation, "skip", nil)
	if err == nil {
		t.Fatal("expected error for invalid transition IDLE->EXPLOITATION")
	}
}

func TestPauseResume(t *testing.T) {
	s := NewState("test-scan-3")
	s.Start()
	s.Advance("auto", nil) // -> DISCOVERY

	// Pause
	if err := s.Pause("user paused"); err != nil {
		t.Fatalf("Pause() failed: %v", err)
	}
	if s.Current() != PhasePaused {
		t.Fatalf("expected PAUSED, got %s", s.Current())
	}

	// Resume should go back to DISCOVERY
	if err := s.Resume(); err != nil {
		t.Fatalf("Resume() failed: %v", err)
	}
	if s.Current() != PhaseDiscovery {
		t.Fatalf("expected DISCOVERY after resume, got %s", s.Current())
	}
}

func TestToMap(t *testing.T) {
	s := NewState("test-scan-4")
	s.Start()
	s.Advance("found 10 URLs", map[string]interface{}{"urls_found": 10})

	m := s.ToMap()
	if m["scan_id"] != "test-scan-4" {
		t.Fatalf("expected scan_id test-scan-4, got %v", m["scan_id"])
	}
	if m["current_phase"] != "discovery" {
		t.Fatalf("expected phase discovery, got %v", m["current_phase"])
	}
}
