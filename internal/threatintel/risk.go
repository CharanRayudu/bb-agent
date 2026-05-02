package threatintel

import (
	"math"
	"sort"
	"strings"
)

// RiskWeights controls the composite risk score formula.
// All weights must sum to 1.0.
type RiskWeights struct {
	CVSS          float64 // base severity weight
	EPSS          float64 // exploit probability weight
	KEVBonus      float64 // bonus for CISA KEV membership (binary)
	ChainDepth    float64 // bonus for being in a multi-step attack chain
	SeverityScore float64 // Mirage severity category weight
}

var defaultWeights = RiskWeights{
	CVSS:          0.30,
	EPSS:          0.25,
	KEVBonus:      0.15,
	ChainDepth:    0.20,
	SeverityScore: 0.10,
}

// RankedFinding is a finding annotated with its composite risk score.
type RankedFinding struct {
	FindingType   string   `json:"finding_type"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Confidence    float64  `json:"confidence"`
	RiskScore     float64  `json:"risk_score"`     // 0–100
	RiskLabel     string   `json:"risk_label"`
	CVSS          float64  `json:"cvss,omitempty"`
	EPSSScore     float64  `json:"epss_score,omitempty"`
	EPSSPct       float64  `json:"epss_percentile,omitempty"`
	InKEV         bool     `json:"in_kev"`
	CVEIDs        []string `json:"cve_ids,omitempty"`
	ChainDepth    int      `json:"chain_depth"`
	ChainImpact   string   `json:"chain_impact,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
	Target        string   `json:"target,omitempty"`
	FlowID        string   `json:"flow_id,omitempty"`
}

// PrioritizationReport is the output of the risk scoring engine.
type PrioritizationReport struct {
	TotalFindings    int              `json:"total_findings"`
	Critical         int              `json:"critical_count"`
	High             int              `json:"high_count"`
	Medium           int              `json:"medium_count"`
	Low              int              `json:"low_count"`
	KEVCount         int              `json:"kev_count"`
	AvgRiskScore     float64          `json:"avg_risk_score"`
	TopRiskScore     float64          `json:"top_risk_score"`
	RankedFindings   []RankedFinding  `json:"ranked_findings"`
	GeneratedAt      string           `json:"generated_at"`
}

// CompositeRiskScore computes a 0–100 risk score.
//
// Parameters:
//   cvss        — CVSS v3 base score (0–10); 0 if unknown
//   epss        — pointer to EPSSScore; nil if unknown
//   inKEV       — whether CVE is in CISA KEV catalog
//   chainDepth  — attack chain depth this finding participates in (0 = isolated)
//   severity    — Mirage severity string ("critical","high","medium","low","info")
func CompositeRiskScore(cvss float64, epss *EPSSScore, inKEV bool, chainDepth int, severity string) float64 {
	w := defaultWeights

	// CVSS component (0–10 → 0–1)
	cvssNorm := math.Min(cvss/10.0, 1.0)
	if cvss == 0 {
		// Fall back to severity-derived CVSS estimate
		cvssNorm = severityToCVSS(severity) / 10.0
	}

	// EPSS component (already 0–1)
	var epssNorm float64
	if epss != nil {
		epssNorm = epss.EPSS
	}

	// KEV component (binary: 0 or 1)
	kevNorm := 0.0
	if inKEV {
		kevNorm = 1.0
	}

	// Chain depth component (deeper = higher risk; diminishing returns)
	chainNorm := math.Min(float64(chainDepth)*0.25, 1.0)

	// Severity score (for findings without CVSS)
	sevNorm := severityToCVSS(severity) / 10.0

	score := (cvssNorm * w.CVSS * 100) +
		(epssNorm * w.EPSS * 100) +
		(kevNorm * w.KEVBonus * 100) +
		(chainNorm * w.ChainDepth * 100) +
		(sevNorm * w.SeverityScore * 100)

	return math.Min(math.Round(score*10)/10, 100)
}

// RiskLabel returns a human-readable label for a composite risk score.
func RiskLabel(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// FindingInput is the input record type for RankFindings.
type FindingInput struct {
	Type       string
	Title      string
	Severity   string
	Confidence float64
	CVSSScore  float64
	CVEIDs     []string
	Target     string
	FlowID     string
}

// RankFindings takes raw finding data and produces a sorted, risk-scored list.
// chainDepths maps findingType → chain depth (0 = not in any chain).
// epssMap maps CVE ID → EPSSScore.
// kevMap maps CVE ID → bool.
func RankFindings(
	findings []FindingInput,
	chainDepths map[string]int,
	chainImpacts map[string]string,
	epssMap map[string]*EPSSScore,
	kevSet map[string]bool,
) PrioritizationReport {

	var ranked []RankedFinding
	sevCounts := map[string]int{}
	var totalScore float64
	kevCount := 0

	for _, f := range findings {
		sevCounts[f.Severity]++

		// Best EPSS/KEV across all CVEs for this finding
		var bestEPSS *EPSSScore
		inKEV := false
		var bestCVSS float64 = f.CVSSScore

		for _, cve := range f.CVEIDs {
			if epss, ok := epssMap[cve]; ok {
				if bestEPSS == nil || epss.EPSS > bestEPSS.EPSS {
					bestEPSS = epss
				}
			}
			if kevSet[cve] {
				inKEV = true
			}
		}

		if inKEV {
			kevCount++
		}

		depth := chainDepths[f.Type]
		impact := chainImpacts[f.Type]

		score := CompositeRiskScore(bestCVSS, bestEPSS, inKEV, depth, f.Severity)
		totalScore += score

		rf := RankedFinding{
			FindingType: f.Type,
			Title:       f.Title,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			RiskScore:   score,
			RiskLabel:   RiskLabel(score),
			CVSS:        bestCVSS,
			InKEV:       inKEV,
			CVEIDs:      f.CVEIDs,
			ChainDepth:  depth,
			ChainImpact: impact,
			Target:      f.Target,
			FlowID:      f.FlowID,
		}
		if bestEPSS != nil {
			rf.EPSSScore = bestEPSS.EPSS
			rf.EPSSPct = bestEPSS.Percentile
		}

		ranked = append(ranked, rf)
	}

	// Sort by risk score descending, then severity
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].RiskScore != ranked[j].RiskScore {
			return ranked[i].RiskScore > ranked[j].RiskScore
		}
		return severityRank(ranked[i].Severity) > severityRank(ranked[j].Severity)
	})

	avg := 0.0
	top := 0.0
	if len(ranked) > 0 {
		avg = math.Round(totalScore/float64(len(ranked))*10) / 10
		top = ranked[0].RiskScore
	}

	return PrioritizationReport{
		TotalFindings:  len(ranked),
		Critical:       sevCounts["critical"],
		High:           sevCounts["high"],
		Medium:         sevCounts["medium"],
		Low:            sevCounts["low"],
		KEVCount:       kevCount,
		AvgRiskScore:   avg,
		TopRiskScore:   top,
		RankedFindings: ranked,
	}
}

func severityToCVSS(sev string) float64 {
	switch strings.ToLower(sev) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 1.0
	}
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
