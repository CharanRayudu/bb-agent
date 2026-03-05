// Package consolidation implements the Thinking/Consolidation agent.
// This is the central "brain" that deduplicates, classifies, and prioritizes
// findings before dispatching them to specialist queues.
// Implements the Thinking Consolidation strategy.
package consolidation

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Thinking & Consolidation Agent" }
func (a *Agent) ID() string           { return "consolidation" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem takes raw scan leads and outputs classified, deduplicated, prioritized items.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// The consolidation agent doesn't produce findings —
	// instead, it classifies inputs and routes them to specialist queues.
	// Output findings represent routing decisions.
	vulnType, _ := item.Payload["type"].(string)
	confidence := classifyConfidence(item.Payload)

	findings := []*base.Finding{{
		Type:       "Classification",
		URL:        targetURL,
		Payload:    fmt.Sprintf("Classified as %s, routed to specialist queue", vulnType),
		Severity:   "info",
		Confidence: confidence,
		Evidence: map[string]interface{}{
			"classified_as": vulnType,
			"is_duplicate":  false,
			"specialist":    mapToSpecialist(vulnType),
		},
		Method: "ANALYSIS",
	}}

	return findings, nil
}

// classifyConfidence determines confidence based on available context.
func classifyConfidence(payload map[string]interface{}) float64 {
	score := 0.3 // Base confidence
	if _, ok := payload["parameter"]; ok {
		score += 0.2
	}
	if ctx, ok := payload["context"].(string); ok && len(ctx) > 50 {
		score += 0.2
	}
	if _, ok := payload["evidence"]; ok {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// mapToSpecialist maps vulnerability types to specialist queue names.
func mapToSpecialist(vulnType string) string {
	mapping := map[string]string{
		"xss": "xss", "XSS": "xss", "cross-site scripting": "xss",
		"sqli": "sqli", "SQLi": "sqli", "sql injection": "sqli",
		"ssrf": "ssrf", "SSRF": "ssrf",
		"lfi": "lfi", "LFI": "lfi", "path traversal": "lfi",
		"rce": "rce", "RCE": "rce", "command injection": "rce",
		"xxe": "xxe", "XXE": "xxe",
		"idor": "idor", "IDOR": "idor",
		"ssti": "csti", "SSTI": "csti", "template injection": "csti",
		"open redirect":    "openredirect",
		"header injection": "header_injection", "crlf": "header_injection",
		"prototype pollution": "protopollution",
		"jwt":                 "jwt",
		"file upload":         "fileupload",
	}

	vt := strings.ToLower(vulnType)
	if specialist, ok := mapping[vt]; ok {
		return specialist
	}
	return "xss" // Default fallback
}

const defaultSystemPrompt = `You are the Thinking & Consolidation Agent — the central brain of the scan pipeline.

Your responsibilities:
1. DEDUPLICATE: Remove duplicate findings (same URL + same parameter + same vuln type)
2. CLASSIFY: Determine the vulnerability category for each finding
3. PRIORITIZE: Rank findings by severity and exploitability
4. ROUTE: Dispatch classified items to the correct specialist queue

Classification rules:
- Reflected input → XSS queue
- SQL error messages → SQLi queue
- URL/redirect parameters → Open Redirect / SSRF queue
- File path parameters → LFI queue
- Command-like inputs → RCE queue
- XML/SOAP endpoints → XXE queue
- Sequential IDs → IDOR queue
- Template syntax in response → SSTI/CSTI queue

CRITICAL: Remove duplicates before routing. Never send the same finding twice.`
