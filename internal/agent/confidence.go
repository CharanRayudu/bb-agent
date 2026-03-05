// Package agent provides confidence scoring and victory hierarchy.
// Provides confidence scoring logic.
//
// The Victory Hierarchy prevents wasting time once a high-impact payload
// succeeds — stop immediately on cookie/domain access, continue testing
// only for low-impact reflections.
package agent

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Confidence calculation
// ---------------------------------------------------------------------------

// CalculateConfidence scores a reflection's exploitability (0.0–1.0).
//
// Scoring:
//   - Base: 0.5
//   - Unencoded: +0.30
//   - Context bonus: +0.05 to +0.15
//   - Visual marker: +0.05
func CalculateConfidence(encoded bool, context, payload string) float64 {
	confidence := 0.5

	if !encoded {
		confidence += 0.30
	}

	switch context {
	case "javascript", "script":
		confidence += 0.15
	case "event_handler", "attribute_value":
		confidence += 0.10
	case "html_text", "html_body":
		confidence += 0.05
	}

	if strings.Contains(payload, "MIRAGE-PWN") || strings.Contains(payload, "mirage-pwn") {
		confidence += 0.05
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

// ---------------------------------------------------------------------------
// Impact tier classification
// ---------------------------------------------------------------------------

// ImpactTier classifies a successful payload's impact level.
//
// Tiers:
//
//	3 = MAXIMUM IMPACT (cookie/domain access) — stop immediately
//	2 = HIGH IMPACT (fetch, XMLHttpRequest, storage) — stop immediately
//	1 = MEDIUM IMPACT (alert executed) — try one more to escalate
//	0 = LOW IMPACT (reflection only) — continue testing
func ImpactTier(payload string, evidence map[string]interface{}) int {
	combined := strings.ToLower(payload + " " + fmt.Sprint(evidence))

	// Tier 3: Maximum — cookie/domain access
	if strings.Contains(combined, "document.cookie") || strings.Contains(combined, "document.domain") {
		return 3
	}

	// Tier 2: High — data exfil capability
	for _, ind := range []string{"localstorage", "sessionstorage", "fetch(", "xmlhttprequest"} {
		if strings.Contains(combined, ind) {
			return 2
		}
	}

	// Tier 1: Medium — confirmed execution
	for _, ind := range []string{"alert(", "confirm(", "prompt(", "eval("} {
		if strings.Contains(combined, ind) {
			return 1
		}
	}

	return 0
}

// ---------------------------------------------------------------------------
// Victory Hierarchy — stop-testing decision
// ---------------------------------------------------------------------------

// ShouldStopTesting determines if further testing is unnecessary based on
// the Victory Hierarchy. Returns (shouldStop, reason).
//
// Rules:
//   - Tier ≥ 3 (cookie/domain): stop immediately
//   - Tier ≥ 2 (exfil): stop immediately
//   - Tier ≥ 1 + prior success: stop (gave it a chance to escalate)
//   - 2+ successes regardless: stop
func ShouldStopTesting(payload string, evidence map[string]interface{}, priorSuccessCount int) (bool, string) {
	tier := ImpactTier(payload, evidence)

	if tier >= 3 {
		return true, "MAXIMUM IMPACT: Cookie/Domain access achieved"
	}
	if tier >= 2 {
		return true, "HIGH IMPACT: Data exfiltration capability confirmed"
	}
	if tier >= 1 && priorSuccessCount >= 1 {
		return true, "Execution confirmed, escalation attempted"
	}
	if priorSuccessCount >= 2 {
		return true, "2 successful payloads found, moving on"
	}
	return false, ""
}
