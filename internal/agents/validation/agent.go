// Package validation implements the Agentic Validator agent.
// Uses multi-strategy validation (LLM analysis, headless browser, OOB)
// to verify findings and reject false positives.
// Implements the Agentic Validator.
package validation

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// ValidationStrategy describes how to verify a finding.
type ValidationStrategy string

const (
	StrategyReplay   ValidationStrategy = "replay"   // Replay the request and check response
	StrategyHeadless ValidationStrategy = "headless" // Use headless browser for client-side vulns
	StrategyOOB      ValidationStrategy = "oob"      // Check OOB callback server for interactions
	StrategyCompare  ValidationStrategy = "compare"  // Compare response with/without payload
	StrategyLLM      ValidationStrategy = "llm"      // Ask LLM to analyze the evidence
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Validation Agent" }
func (a *Agent) ID() string           { return "validation" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnType, _ := item.Payload["type"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Select validation strategies based on vulnerability type
	strategies := selectStrategies(vulnType)

	var findings []*base.Finding
	for _, strategy := range strategies {
		findings = append(findings, &base.Finding{
			Type:       "Validation",
			URL:        targetURL,
			Payload:    fmt.Sprintf("Validate %s using %s strategy", vulnType, strategy),
			Severity:   "info",
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"strategy":      string(strategy),
				"original_type": vulnType,
				"validated":     false, // Set to true upon successful validation
			},
			Method: "VALIDATION",
		})
	}
	return findings, nil
}

// selectStrategies picks the best validation approach for each vuln type.
func selectStrategies(vulnType string) []ValidationStrategy {
	switch vulnType {
	case "XSS":
		return []ValidationStrategy{StrategyHeadless, StrategyOOB, StrategyLLM}
	case "SQLi":
		return []ValidationStrategy{StrategyReplay, StrategyCompare, StrategyLLM}
	case "SSRF":
		return []ValidationStrategy{StrategyOOB, StrategyReplay}
	case "LFI":
		return []ValidationStrategy{StrategyReplay, StrategyCompare}
	case "RCE":
		return []ValidationStrategy{StrategyOOB, StrategyReplay}
	case "XXE":
		return []ValidationStrategy{StrategyOOB, StrategyReplay}
	case "IDOR":
		return []ValidationStrategy{StrategyCompare, StrategyLLM}
	case "SSTI":
		return []ValidationStrategy{StrategyReplay, StrategyCompare}
	case "Open Redirect":
		return []ValidationStrategy{StrategyReplay, StrategyHeadless}
	case "JWT":
		return []ValidationStrategy{StrategyReplay, StrategyLLM}
	default:
		return []ValidationStrategy{StrategyLLM, StrategyReplay}
	}
}

const defaultSystemPrompt = `You are the Agentic Validator -- the final gate before a finding is confirmed.

Validation strategies:
1. REPLAY -- Re-send the exact exploit request, verify the vulnerability triggers
2. HEADLESS -- Use a headless browser for client-side vulns (XSS, DOM-based)
3. OOB -- Check the Interactsh callback server for out-of-band interactions
4. COMPARE -- Compare response with/without payload (for blind vulns)
5. LLM -- Analyze the evidence with LLM reasoning as a last resort

Validation rules:
- XSS: Prefer headless browser (check for JS execution / DOM changes)
- SQLi: Prefer replay + response comparison (check for error strings)
- SSRF: Prefer OOB callback verification
- RCE: Prefer OOB callback (never trust response content alone)
- IDOR: Prefer response comparison (different user contexts)

CRITICAL: Reject any finding that cannot be independently verified.
A high-confidence finding with no validation is a FALSE POSITIVE.`
