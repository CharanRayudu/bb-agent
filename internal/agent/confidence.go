// Package agent provides confidence scoring, cognitive reasoning framework,
// and victory hierarchy for the autonomous pentest engine.
//
// The Confidence Engine implements the KNOW-THINK-TEST-VALIDATE cognitive loop
// inspired by Cyber-AutoAgent's confidence-driven reasoning. It drives every
// decision in the P-E-R framework by tracking what is confirmed vs hypothesized.
//
// The Victory Hierarchy prevents wasting time once a high-impact payload
// succeeds -- stop immediately on cookie/domain access, continue testing
// only for low-impact reflections.
package agent

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CognitiveStep represents one cycle of the KNOW-THINK-TEST-VALIDATE loop.
type CognitiveStep struct {
	Step       int       `json:"step"`
	Know       string    `json:"know"`       // What is confirmed?
	Think      string    `json:"think"`      // Hypothesis with confidence
	Test       string    `json:"test"`       // Minimal action for max information
	Validate   string    `json:"validate"`   // Evidence confirms/refutes
	Confidence float64   `json:"confidence"` // 0-100%
	Timestamp  time.Time `json:"timestamp"`
}

// ConfidenceThresholds defines the decision boundaries for the confidence engine.
type ConfidenceThresholds struct {
	DirectExploit  float64 // >80%: proceed with direct exploitation
	HypothesisTest float64 // 50-80%: test hypothesis first
	PivotOrSwarm   float64 // <50%: pivot strategy or deploy swarm
	StopTesting    float64 // >95%: stop, finding confirmed
	AbandonPath    float64 // <20%: abandon this attack path
}

// DefaultConfidenceThresholds returns production-ready threshold values.
func DefaultConfidenceThresholds() ConfidenceThresholds {
	return ConfidenceThresholds{
		DirectExploit:  80.0,
		HypothesisTest: 50.0,
		PivotOrSwarm:   50.0,
		StopTesting:    95.0,
		AbandonPath:    20.0,
	}
}

// ConfidenceEngine tracks confidence across cognitive steps and makes
// autonomous decisions about whether to exploit, test, pivot, or stop.
type ConfidenceEngine struct {
	thresholds ConfidenceThresholds
	steps      []CognitiveStep
	mu         sync.RWMutex
}

// NewConfidenceEngine creates a new engine with the given thresholds.
func NewConfidenceEngine(thresholds ConfidenceThresholds) *ConfidenceEngine {
	return &ConfidenceEngine{
		thresholds: thresholds,
		steps:      make([]CognitiveStep, 0),
	}
}

// ConfidenceAction is the recommended action based on current confidence.
type ConfidenceAction string

const (
	ActionExploit  ConfidenceAction = "exploit"   // Confidence high: go for it
	ActionTest     ConfidenceAction = "test"       // Moderate: hypothesis testing
	ActionPivot    ConfidenceAction = "pivot"      // Low: try different approach
	ActionSwarm    ConfidenceAction = "swarm"      // Low: deploy parallel agents
	ActionStop     ConfidenceAction = "stop"       // Very high: confirmed, done
	ActionAbandon  ConfidenceAction = "abandon"    // Very low: give up on this path
)

// Decide returns the recommended action for the current confidence level.
func (ce *ConfidenceEngine) Decide(confidence float64) ConfidenceAction {
	switch {
	case confidence >= ce.thresholds.StopTesting:
		return ActionStop
	case confidence >= ce.thresholds.DirectExploit:
		return ActionExploit
	case confidence >= ce.thresholds.HypothesisTest:
		return ActionTest
	case confidence <= ce.thresholds.AbandonPath:
		return ActionAbandon
	default:
		return ActionPivot
	}
}

// RecordStep adds a new KNOW-THINK-TEST-VALIDATE cycle.
func (ce *ConfidenceEngine) RecordStep(know, think, test, validate string, confidence float64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	step := CognitiveStep{
		Step:       len(ce.steps) + 1,
		Know:       know,
		Think:      think,
		Test:       test,
		Validate:   validate,
		Confidence: confidence,
		Timestamp:  time.Now(),
	}
	ce.steps = append(ce.steps, step)
}

// CurrentConfidence returns the most recent confidence score.
func (ce *ConfidenceEngine) CurrentConfidence() float64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if len(ce.steps) == 0 {
		return 50.0 // neutral default
	}
	return ce.steps[len(ce.steps)-1].Confidence
}

// Trend returns the confidence trend direction ("rising", "falling", "stable").
func (ce *ConfidenceEngine) Trend() string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if len(ce.steps) < 3 {
		return "stable"
	}

	recent := ce.steps[len(ce.steps)-3:]
	delta := recent[2].Confidence - recent[0].Confidence
	if delta > 10 {
		return "rising"
	}
	if delta < -10 {
		return "falling"
	}
	return "stable"
}

// Steps returns a copy of all recorded cognitive steps.
func (ce *ConfidenceEngine) Steps() []CognitiveStep {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	out := make([]CognitiveStep, len(ce.steps))
	copy(out, ce.steps)
	return out
}

// GeneratePromptBlock creates a prompt insertion for the LLM that encodes
// the confidence-driven reasoning framework.
func (ce *ConfidenceEngine) GeneratePromptBlock() string {
	action := ce.Decide(ce.CurrentConfidence())
	trend := ce.Trend()

	return fmt.Sprintf(`## CONFIDENCE-DRIVEN REASONING FRAMEWORK

Current Confidence: %.1f%% (Trend: %s)
Recommended Action: %s

Every step MUST follow this cognitive loop:
1. KNOW: What is confirmed? What constraints have been learned?
2. THINK: Form a hypothesis with confidence score (0-100%%).
3. TEST: Take the minimal action for maximum information gain.
4. VALIDATE: Does the evidence confirm or refute? Update confidence.

Decision Thresholds:
- >%.0f%%: Proceed with DIRECT EXPLOITATION
- %.0f%%-%.0f%%: HYPOTHESIS TESTING first
- <%.0f%%: PIVOT strategy or deploy parallel swarm
- >%.0f%%: STOP -- finding confirmed with proof
- <%.0f%%: ABANDON this attack path

IMPORTANT: Do not spray payloads. Each action should be deliberate and
confidence-informed. If confidence is falling, pivot early.`,
		ce.CurrentConfidence(), trend, action,
		ce.thresholds.DirectExploit,
		ce.thresholds.HypothesisTest, ce.thresholds.DirectExploit,
		ce.thresholds.PivotOrSwarm,
		ce.thresholds.StopTesting,
		ce.thresholds.AbandonPath,
	)
}

// Reset clears all recorded steps.
func (ce *ConfidenceEngine) Reset() {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.steps = make([]CognitiveStep, 0)
}

// ---------------------------------------------------------------------------
// Payload-specific confidence (backward compatible with existing code)
// ---------------------------------------------------------------------------

// CalculateConfidence scores a reflection's exploitability (0.0-1.0).
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
//	3 = MAXIMUM IMPACT (cookie/domain access) -- stop immediately
//	2 = HIGH IMPACT (fetch, XMLHttpRequest, storage) -- stop immediately
//	1 = MEDIUM IMPACT (alert executed) -- try one more to escalate
//	0 = LOW IMPACT (reflection only) -- continue testing
func ImpactTier(payload string, evidence map[string]interface{}) int {
	combined := strings.ToLower(payload + " " + fmt.Sprint(evidence))

	if strings.Contains(combined, "document.cookie") || strings.Contains(combined, "document.domain") {
		return 3
	}

	for _, ind := range []string{"localstorage", "sessionstorage", "fetch(", "xmlhttprequest"} {
		if strings.Contains(combined, ind) {
			return 2
		}
	}

	for _, ind := range []string{"alert(", "confirm(", "prompt(", "eval("} {
		if strings.Contains(combined, ind) {
			return 1
		}
	}

	return 0
}

// ShouldStopTesting determines if further testing is unnecessary.
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
