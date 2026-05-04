package posture_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/posture"
)

// ── Compute ───────────────────────────────────────────────────────────────────

func TestCompute_EmptyInput(t *testing.T) {
	snap := posture.Compute(posture.Input{})
	if snap.Score < 0 || snap.Score > 100 {
		t.Errorf("Score = %.1f, want 0-100", snap.Score)
	}
	if snap.Grade == "" {
		t.Error("Grade should not be empty")
	}
	if snap.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if len(snap.OWASPCoverage) != 10 {
		t.Errorf("OWASPCoverage length = %d, want 10", len(snap.OWASPCoverage))
	}
	if len(snap.UrgentActions) == 0 {
		t.Error("UrgentActions should not be empty even with no findings")
	}
}

func TestCompute_PerfectPosture(t *testing.T) {
	snap := posture.Compute(posture.Input{
		FindingCounts: map[string]int{},
		RemItems:      5,
		RemFixed:      5,
		SLACompliant:  5,
		MonitorCount:  3,
		UniqueTargets: 3,
		OpenCritical:  0,
		OpenHigh:      0,
	})
	if snap.Score < 80 {
		t.Errorf("expected high score for perfect posture, got %.1f", snap.Score)
	}
	if snap.Grade != "A" && snap.Grade != "B" {
		t.Errorf("expected A or B grade for perfect posture, got %s", snap.Grade)
	}
}

func TestCompute_CriticalFindings_LowersScore(t *testing.T) {
	noFindings := posture.Compute(posture.Input{})
	withCritical := posture.Compute(posture.Input{
		FindingCounts: map[string]int{"critical": 5, "high": 10},
		OpenCritical:  5,
		OpenHigh:      10,
	})
	if withCritical.Score >= noFindings.Score {
		t.Errorf("critical findings should lower score: withCritical=%.1f, noFindings=%.1f",
			withCritical.Score, noFindings.Score)
	}
}

func TestCompute_GradeMapping(t *testing.T) {
	cases := []struct {
		input   posture.Input
		inRange func(g string) bool
	}{
		{
			// Perfect: should be A
			posture.Input{RemItems: 10, RemFixed: 10, SLACompliant: 10, MonitorCount: 5, UniqueTargets: 5},
			func(g string) bool { return g == "A" || g == "B" },
		},
		{
			// Many criticals: should be D or F
			posture.Input{OpenCritical: 10, OpenHigh: 20, FindingCounts: map[string]int{"critical": 10, "high": 20}},
			func(g string) bool { return g == "D" || g == "F" || g == "C" },
		},
	}
	for _, c := range cases {
		snap := posture.Compute(c.input)
		if !c.inRange(snap.Grade) {
			t.Errorf("unexpected grade %q for input %+v, score=%.1f", snap.Grade, c.input, snap.Score)
		}
	}
}

func TestCompute_OWASPCoverage(t *testing.T) {
	snap := posture.Compute(posture.Input{
		FindingTypes:  []string{"SQL Injection", "XSS", "SSRF"},
		FindingCounts: map[string]int{"high": 3},
	})

	exposed := map[string]bool{}
	for _, cat := range snap.OWASPCoverage {
		if cat.Exposed {
			exposed[cat.ID] = true
		}
	}

	// SQL Injection → A03:2025 (Injection)
	if !exposed["A03:2025"] {
		t.Error("expected A03:2025 (Injection) to be exposed by SQLi finding")
	}
	// SSRF → A10:2025
	if !exposed["A10:2025"] {
		t.Error("expected A10:2025 (SSRF) to be exposed by SSRF finding")
	}
}

func TestCompute_OWASPCategories_AllHave2025IDs(t *testing.T) {
	snap := posture.Compute(posture.Input{})
	for _, cat := range snap.OWASPCoverage {
		if len(cat.ID) < 8 {
			t.Errorf("OWASP category ID too short: %q", cat.ID)
		}
		// All IDs should end with :2025
		if len(cat.ID) >= 5 && cat.ID[len(cat.ID)-5:] != ":2025" {
			t.Errorf("OWASP category ID should end with :2025, got %q", cat.ID)
		}
	}
}

func TestCompute_UrgentActions_CriticalFirst(t *testing.T) {
	snap := posture.Compute(posture.Input{
		FindingCounts: map[string]int{"critical": 3, "high": 5},
		OpenCritical:  3,
		OpenHigh:      5,
		SLABreached:   2,
	})

	if len(snap.UrgentActions) == 0 {
		t.Fatal("expected urgent actions")
	}
	first := snap.UrgentActions[0]
	if first.Severity != "critical" {
		t.Errorf("first urgent action severity = %q, want critical", first.Severity)
	}
	if first.Priority != 1 {
		t.Errorf("first action priority = %d, want 1", first.Priority)
	}
}

func TestCompute_UrgentActions_MaxFive(t *testing.T) {
	snap := posture.Compute(posture.Input{
		FindingCounts: map[string]int{"critical": 10, "high": 10},
		OpenCritical:  10,
		OpenHigh:      10,
		SLABreached:   5,
		UniqueTargets: 3,
		MonitorCount:  0,
	})
	if len(snap.UrgentActions) > 5 {
		t.Errorf("UrgentActions length = %d, want ≤5", len(snap.UrgentActions))
	}
}

func TestCompute_ScoreRange(t *testing.T) {
	cases := []posture.Input{
		{},
		{OpenCritical: 100, FindingCounts: map[string]int{"critical": 100}},
		{RemItems: 1000, RemFixed: 1000, SLACompliant: 1000, MonitorCount: 100, UniqueTargets: 100},
	}
	for _, in := range cases {
		snap := posture.Compute(in)
		if snap.Score < 0 || snap.Score > 100 {
			t.Errorf("Score %.1f out of range [0,100]", snap.Score)
		}
	}
}

// ── HistoryStore ──────────────────────────────────────────────────────────────

func TestHistoryStore_PushAndAll(t *testing.T) {
	h := posture.NewHistoryStore()

	if snaps := h.All(); len(snaps) != 0 {
		t.Errorf("expected empty history, got %d", len(snaps))
	}

	for i := 0; i < 3; i++ {
		snap := posture.Compute(posture.Input{OpenCritical: i})
		h.Push(snap)
	}

	snaps := h.All()
	if len(snaps) != 3 {
		t.Errorf("All() = %d, want 3", len(snaps))
	}
}

func TestHistoryStore_Eviction(t *testing.T) {
	h := posture.NewHistoryStore()

	// Push 95 snapshots into a store capped at 90
	for i := 0; i < 95; i++ {
		h.Push(posture.Compute(posture.Input{OpenCritical: i % 5}))
	}

	snaps := h.All()
	if len(snaps) != 90 {
		t.Errorf("expected 90 snapshots after eviction, got %d", len(snaps))
	}
}
