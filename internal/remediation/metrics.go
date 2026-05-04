package remediation

import "time"

// Metrics aggregates remediation programme KPIs.
type Metrics struct {
	Total         int            `json:"total"`
	ByStatus      map[string]int `json:"by_status"`
	BySeverity    map[string]int `json:"by_severity"`
	SLABreached   int            `json:"sla_breached"`
	SLACompliant  int            `json:"sla_compliant"`
	FixedThisWeek int            `json:"fixed_this_week"`
	MTTRDays      float64        `json:"mttr_days"`    // mean time to remediate (fixed/verified items)
	RiskReduced   float64        `json:"risk_reduced"` // sum of risk scores of fixed items
	OpenRisk      float64        `json:"open_risk"`    // sum of risk scores of open items
}

// ComputeMetrics calculates programme-level KPIs from a list of items.
func ComputeMetrics(items []*Item) Metrics {
	m := Metrics{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
	}
	now := time.Now()
	weekAgo := now.Add(-7 * 24 * time.Hour)

	var totalRemedHours float64
	var remediatedCount int

	for _, it := range items {
		m.Total++
		m.ByStatus[string(it.Status)]++
		m.BySeverity[it.Severity]++

		// SLA tracking (only for non-terminal items)
		if !it.IsTerminal() && it.SLADeadline != nil {
			if now.After(*it.SLADeadline) {
				m.SLABreached++
			} else {
				m.SLACompliant++
			}
			if it.Status == StatusOpen {
				m.OpenRisk += it.RiskScore
			}
		}

		// Fixed this week
		if (it.Status == StatusFixed || it.Status == StatusVerified) && it.FixedAt != nil && it.FixedAt.After(weekAgo) {
			m.FixedThisWeek++
		}

		// MTTR calculation
		if (it.Status == StatusFixed || it.Status == StatusVerified) && it.FixedAt != nil {
			m.RiskReduced += it.RiskScore
			totalRemedHours += it.FixedAt.Sub(it.CreatedAt).Hours()
			remediatedCount++
		}
	}

	if remediatedCount > 0 {
		m.MTTRDays = (totalRemedHours / float64(remediatedCount)) / 24.0
	}

	return m
}
