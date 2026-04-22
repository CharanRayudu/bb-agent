package agent

import (
	"math"
	"strings"
	"time"
)

// APTSConfidenceScore represents an APTS RP-003 compliant confidence score
// with component breakdown for transparency.
type APTSConfidenceScore struct {
	Total                  int     `json:"total"`                   // 0-100 composite
	EvidenceQuality        float64 `json:"evidence_quality"`        // 30% weight
	IndependentConfirmation float64 `json:"independent_confirmation"` // 25% weight
	EnvironmentalFactors   float64 `json:"environmental_factors"`   // 20% weight
	HistoricalAccuracy     float64 `json:"historical_accuracy"`     // 15% weight
	Recency                float64 `json:"recency"`                 // 10% weight
	ConfirmationStatus     string  `json:"confirmation_status"`     // "Confirmed" | "Unconfirmed"
}

// CalculateAPTSConfidence computes the OWASP APTS RP-003 composite confidence
// score for a finding based on five weighted factors.
func CalculateAPTSConfidence(f *Finding, platformTP map[string]float64) APTSConfidenceScore {
	eq := evidenceQualityScore(f)
	ic := independentConfirmationScore(f)
	ef := environmentalFactorScore(f)
	ha := historicalAccuracyScore(f, platformTP)
	rec := recencyScore(f)

	// Weighted composite: 30 + 25 + 20 + 15 + 10 = 100
	total := math.Round(eq*30 + ic*25 + ef*20 + ha*15 + rec*10)
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	status := "Unconfirmed"
	if int(total) >= 50 && hasConcreteProof(f) {
		status = "Confirmed"
	}

	return APTSConfidenceScore{
		Total:                  int(total),
		EvidenceQuality:        math.Round(eq*100) / 100,
		IndependentConfirmation: math.Round(ic*100) / 100,
		EnvironmentalFactors:   math.Round(ef*100) / 100,
		HistoricalAccuracy:     math.Round(ha*100) / 100,
		Recency:                math.Round(rec*100) / 100,
		ConfirmationStatus:     status,
	}
}

// evidenceQualityScore returns 0-1 for evidence quality (30% of total).
// APTS RP-003: direct exploit evidence scores highest; indirect indicators score lower.
func evidenceQualityScore(f *Finding) float64 {
	proof, _ := classifyFindingProof(f)
	switch proof {
	case ProofOOB:
		return 0.95 // OOB callback = highest — active DNS/HTTP interaction
	case ProofRequestResponse:
		return 0.90 // Request/response pair = strong direct evidence
	case ProofBrowser:
		return 0.85 // Browser validation = direct visual confirmation
	case ProofTiming:
		return 0.70 // Timing differential = statistical, slightly weaker
	default:
		// Unclassified: check evidence map for version banners or indirect signals
		if f.Evidence != nil && len(f.Evidence) > 0 {
			return 0.30 // Indirect indicator (version banner, header, etc.)
		}
		return 0.10 // No evidence at all
	}
}

// independentConfirmationScore returns 0-1 based on number of verification methods (25%).
func independentConfirmationScore(f *Finding) float64 {
	methods := 0

	// Count distinct proof signals in the evidence map
	if f.Evidence == nil {
		return 0.25
	}
	if _, ok := f.Evidence["request"]; ok {
		methods++
	}
	if _, ok := f.Evidence["response"]; ok {
		methods++
	}
	if _, ok := f.Evidence["screenshot"]; ok {
		methods++
	}
	if _, ok := f.Evidence["oob_callback"]; ok {
		methods++
	}
	if _, ok := f.Evidence["timing_delta"]; ok {
		methods++
	}

	switch {
	case methods >= 3:
		return 1.0 // Three or more independent methods
	case methods == 2:
		return 0.75
	case methods == 1:
		return 0.50
	default:
		return 0.25
	}
}

// environmentalFactorScore returns 0-1 based on target hardening signals (20%).
// Default/unprotected configs score higher; hardened environments score lower.
func environmentalFactorScore(f *Finding) float64 {
	// Look for defence signals in the finding context
	payload := strings.ToLower(f.Payload + f.URL)
	evidenceStr := ""
	if f.Evidence != nil {
		if r, ok := f.Evidence["response"].(string); ok {
			evidenceStr = strings.ToLower(r)
		}
	}

	hardened := strings.Contains(evidenceStr, "waf") ||
		strings.Contains(evidenceStr, "cloudflare") ||
		strings.Contains(evidenceStr, "akamai") ||
		strings.Contains(evidenceStr, "rate limit") ||
		strings.Contains(payload, "bypass")

	if hardened {
		return 0.40 // Target is hardened — finding less likely to be straightforward
	}
	return 0.80 // Default/unprotected environment
}

// historicalAccuracyScore returns 0-1 based on the platform's true-positive rate
// for this vulnerability class (15%).
func historicalAccuracyScore(f *Finding, platformTP map[string]float64) float64 {
	if platformTP == nil {
		return 0.75 // Default: assume good platform accuracy
	}
	vulnClass := normalizeVulnClass(f.Type)
	if rate, ok := platformTP[vulnClass]; ok {
		return rate
	}
	return 0.75
}

// recencyScore returns 0-1 based on how recently the evidence was gathered (10%).
// APTS RP-003: evidence within 1 hour = 100%, decaying over time.
func recencyScore(f *Finding) float64 {
	if f.Timestamp.IsZero() {
		return 0.50
	}
	age := time.Since(f.Timestamp)
	switch {
	case age <= time.Hour:
		return 1.0
	case age <= 6*time.Hour:
		return 0.85
	case age <= 24*time.Hour:
		return 0.65
	case age <= 7*24*time.Hour:
		return 0.40
	default:
		return 0.20
	}
}

// hasConcreteProof checks if a finding has at least one concrete proof type
// (required alongside confidence ≥ 50 for "Confirmed" status).
func hasConcreteProof(f *Finding) bool {
	proof, _ := classifyFindingProof(f)
	switch proof {
	case ProofRequestResponse, ProofBrowser, ProofOOB, ProofTiming:
		return true
	default:
		return false
	}
}

// normalizeVulnClass maps Finding.Type values to canonical vulnerability class keys.
func normalizeVulnClass(t string) string {
	t = strings.ToLower(t)
	switch {
	case strings.Contains(t, "xss"):
		return "xss"
	case strings.Contains(t, "sqli") || strings.Contains(t, "sql injection"):
		return "sqli"
	case strings.Contains(t, "ssrf"):
		return "ssrf"
	case strings.Contains(t, "idor"):
		return "idor"
	case strings.Contains(t, "rce") || strings.Contains(t, "command injection"):
		return "rce"
	case strings.Contains(t, "lfi") || strings.Contains(t, "path traversal"):
		return "lfi"
	case strings.Contains(t, "auth"):
		return "auth_bypass"
	case strings.Contains(t, "ssti"):
		return "ssti"
	case strings.Contains(t, "xxe"):
		return "xxe"
	default:
		return strings.ReplaceAll(t, " ", "_")
	}
}

// DefaultPlatformTPRates returns baseline true-positive rates per vulnerability class.
// These should be updated from real scan history over time.
var DefaultPlatformTPRates = map[string]float64{
	"xss":          0.82,
	"sqli":         0.78,
	"ssrf":         0.71,
	"idor":         0.68,
	"rce":          0.85,
	"lfi":          0.74,
	"auth_bypass":  0.79,
	"ssti":         0.76,
	"xxe":          0.70,
	"misconfigs":   0.65,
}
