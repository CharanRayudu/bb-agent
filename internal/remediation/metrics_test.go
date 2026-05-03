package remediation_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/remediation"
)

func TestComputeMetrics_Empty(t *testing.T) {
	m := remediation.ComputeMetrics(nil)
	if m.Total != 0 {
		t.Errorf("Total = %d, want 0", m.Total)
	}
	if m.MTTRDays != 0 {
		t.Errorf("MTTRDays = %.2f, want 0", m.MTTRDays)
	}
}

func TestComputeMetrics_Counts(t *testing.T) {
	st := remediation.NewStore()
	st.Create("f1", "SQLi", "d", "critical", "https://t.com", "SQLi", "fl", 9.5)
	st.Create("f2", "XSS", "d", "high", "https://t.com", "XSS", "fl", 7.0)
	st.Create("f3", "CORS", "d", "medium", "https://t.com", "CORS", "fl", 4.0)

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	if m.Total != 3 {
		t.Errorf("Total = %d, want 3", m.Total)
	}
	if m.ByStatus["open"] != 3 {
		t.Errorf("ByStatus[open] = %d, want 3", m.ByStatus["open"])
	}
	if m.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", m.BySeverity["critical"])
	}
}

func TestComputeMetrics_SLABreached(t *testing.T) {
	st := remediation.NewStore()
	// Create item and move through statuses to not-terminal but with SLA
	it1 := st.Create("f1", "A", "d", "critical", "t", "T", "fl", 9.0)
	it2 := st.Create("f2", "B", "d", "high", "t", "T", "fl", 7.0)
	_ = it1
	_ = it2

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	// Critical items have SLA deadlines — within SLA since just created
	if m.SLABreached > 0 {
		t.Errorf("SLABreached = %d, expected 0 for fresh items", m.SLABreached)
	}
	slaTotal := m.SLACompliant + m.SLABreached
	if slaTotal != 2 {
		t.Errorf("SLA tracked = %d, want 2", slaTotal)
	}
}

func TestComputeMetrics_OpenRisk(t *testing.T) {
	st := remediation.NewStore()
	st.Create("f1", "A", "d", "critical", "t", "T", "fl", 9.5)
	st.Create("f2", "B", "d", "high", "t", "T", "fl", 7.0)

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	if m.OpenRisk <= 0 {
		t.Errorf("OpenRisk = %.2f, expected >0 for open critical items", m.OpenRisk)
	}
}

func TestComputeMetrics_FixedThisWeek(t *testing.T) {
	st := remediation.NewStore()
	it := st.Create("f1", "A", "d", "high", "t", "T", "fl", 7.0)
	st.UpdateStatus(it.ID, remediation.StatusFixed, "") //nolint

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	if m.FixedThisWeek != 1 {
		t.Errorf("FixedThisWeek = %d, want 1", m.FixedThisWeek)
	}
}

func TestComputeMetrics_MTTRCalculated(t *testing.T) {
	st := remediation.NewStore()
	it := st.Create("f1", "A", "d", "high", "t", "T", "fl", 7.0)
	st.UpdateStatus(it.ID, remediation.StatusFixed, "") //nolint

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	if m.MTTRDays < 0 {
		t.Errorf("MTTRDays = %.4f, should not be negative", m.MTTRDays)
	}
}

func TestComputeMetrics_RiskReduced(t *testing.T) {
	st := remediation.NewStore()
	it := st.Create("f1", "A", "d", "critical", "t", "T", "fl", 9.5)
	st.UpdateStatus(it.ID, remediation.StatusFixed, "") //nolint

	items := st.List("")
	m := remediation.ComputeMetrics(items)

	if m.RiskReduced != 9.5 {
		t.Errorf("RiskReduced = %.2f, want 9.5", m.RiskReduced)
	}
}
