package monitoring

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// FindingSummary is a lightweight representation of a finding for delta comparison.
type FindingSummary struct {
	Fingerprint string  `json:"fingerprint"` // SHA-256 of type+target+parameter
	Type        string  `json:"type"`
	Title       string  `json:"title"`
	Target      string  `json:"target"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	FlowID      string  `json:"flow_id,omitempty"`
}

// Baseline is a frozen set of finding fingerprints at a point in time.
type Baseline struct {
	MonitorID    string                    `json:"monitor_id"`
	SnapshotAt   time.Time                 `json:"snapshot_at"`
	Fingerprints map[string]FindingSummary `json:"fingerprints"` // fingerprint → summary
}

// Delta captures the difference between a baseline and the current finding set.
type Delta struct {
	MonitorID        string           `json:"monitor_id"`
	ScanID           string           `json:"scan_id,omitempty"`
	ComputedAt       time.Time        `json:"computed_at"`
	NewFindings      []FindingSummary `json:"new_findings"`
	ResolvedFindings []FindingSummary `json:"resolved_findings"` // in baseline but not now
	Regressions      []FindingSummary `json:"regressions"`       // previously resolved, now back
	Unchanged        int              `json:"unchanged"`
	RiskDelta        float64          `json:"risk_delta"` // positive = more risk
	HasCritical      bool             `json:"has_critical"`
	HasHigh          bool             `json:"has_high"`
	Summary          string           `json:"summary"`
}

// FingerprintFinding computes a stable fingerprint for a finding.
// We hash type + target + parameter (lowercased) so findings with the same
// root cause but different response bodies still de-duplicate.
func FingerprintFinding(findingType, target, parameter string) string {
	key := strings.ToLower(fmt.Sprintf("%s|%s|%s", findingType, target, parameter))
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:8]) // 16-char hex prefix is collision-resistant enough
}

// BuildBaseline creates a new Baseline from a set of finding summaries.
func BuildBaseline(monitorID string, findings []FindingSummary) Baseline {
	fps := map[string]FindingSummary{}
	for _, f := range findings {
		fps[f.Fingerprint] = f
	}
	return Baseline{
		MonitorID:    monitorID,
		SnapshotAt:   time.Now(),
		Fingerprints: fps,
	}
}

// ComputeDelta compares a current finding set against a baseline.
func ComputeDelta(monitorID string, baseline Baseline, current []FindingSummary) Delta {
	d := Delta{
		MonitorID:  monitorID,
		ComputedAt: time.Now(),
	}

	currentMap := map[string]FindingSummary{}
	for _, f := range current {
		currentMap[f.Fingerprint] = f
	}

	// New findings: in current but not in baseline
	for fp, f := range currentMap {
		if _, inBaseline := baseline.Fingerprints[fp]; !inBaseline {
			d.NewFindings = append(d.NewFindings, f)
			if f.Severity == "critical" {
				d.HasCritical = true
			}
			if f.Severity == "high" {
				d.HasHigh = true
			}
		} else {
			d.Unchanged++
		}
	}

	// Resolved findings: in baseline but not in current
	for fp, f := range baseline.Fingerprints {
		if _, inCurrent := currentMap[fp]; !inCurrent {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}

	// Risk delta: severity-weighted finding count change
	d.RiskDelta = severityScore(d.NewFindings) - severityScore(d.ResolvedFindings)

	d.Summary = buildSummary(d)
	return d
}

// ComputeDeltaWithPrior compares current findings to a prior delta's resolved set
// to detect regressions (findings that were resolved but have come back).
func ComputeDeltaWithPrior(monitorID string, baseline Baseline, prior Delta, current []FindingSummary) Delta {
	d := ComputeDelta(monitorID, baseline, current)

	// Build a set of previously-resolved fingerprints
	priorResolved := map[string]FindingSummary{}
	for _, f := range prior.ResolvedFindings {
		priorResolved[f.Fingerprint] = f
	}

	// Any "new" finding that was previously resolved is a regression
	var genuinelyNew []FindingSummary
	for _, f := range d.NewFindings {
		if orig, wasResolved := priorResolved[f.Fingerprint]; wasResolved {
			_ = orig
			d.Regressions = append(d.Regressions, f)
		} else {
			genuinelyNew = append(genuinelyNew, f)
		}
	}
	d.NewFindings = genuinelyNew
	d.Summary = buildSummary(d)
	return d
}

func severityScore(findings []FindingSummary) float64 {
	var score float64
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score += 10.0
		case "high":
			score += 7.0
		case "medium":
			score += 4.0
		case "low":
			score += 1.0
		}
	}
	return score
}

func buildSummary(d Delta) string {
	parts := []string{}
	if len(d.NewFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d new finding%s", len(d.NewFindings), plural(len(d.NewFindings))))
	}
	if len(d.Regressions) > 0 {
		parts = append(parts, fmt.Sprintf("%d regression%s", len(d.Regressions), plural(len(d.Regressions))))
	}
	if len(d.ResolvedFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", len(d.ResolvedFindings)))
	}
	if len(parts) == 0 {
		return "No changes since baseline"
	}
	return strings.Join(parts, ", ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
