// Package urlmaster implements the URLMaster Elite agent.
// A vertical orchestrator that owns a single URL's complete lifecycle:
// Recon -> Feature Extraction -> Vulnerability Analysis -> deep-dive Exploitation -> Browser Validation.
package urlmaster

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct {
	systemPrompt string
	validator    *base.VisualValidator
}

func New() *Agent {
	return &Agent{
		systemPrompt: defaultSystemPrompt,
		validator:    base.NewVisualValidator(),
	}
}

func (a *Agent) Name() string         { return "URLMaster (Elite)" }
func (a *Agent) ID() string           { return "urlmaster" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem handles deep-dive analysis of a single URL.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	fmt.Printf("[URLMaster] 🚀 Starting deep analysis of %s\n", targetURL)

	// Phase 1: Feature Extraction & Recon (Internal)
	// Phase 2: Vulnerability Analysis (LLM Thought)
	// Phase 3: Targeted Exploitation (Calling specialist queues)

	// In URLMaster mode, we don't just dump work into the queue and wait.
	// We iterate through a loop of "Thoughts" and "Actions".

	var findings []*base.Finding

	// Simulation of the vertical loop:
	// 1. Extract parameters
	// 2. Identify risks (e.g. search box -> XSS)
	// 3. Test with high-intelligence payloads
	// 4. Validate with Browser

	// Example scenario: XSS deep dive
	isVulnerable, reason, ssPath, err := a.validator.ValidateXSS(ctx, targetURL, "q", "<script>alert(1)</script>", false)
	if err == nil && isVulnerable {
		findings = append(findings, &base.Finding{
			Type:       "XSS (Visual Confirmation)",
			URL:        targetURL,
			Payload:    "<script>alert(1)</script>",
			Severity:   "high",
			Confidence: 1.0,
			Evidence: map[string]interface{}{
				"reason":       reason,
				"screenshot":   ssPath,
				"technique":    "Visual validation",
				"orchestrator": "URLMaster",
			},
		})
	}

	return findings, nil
}

const defaultSystemPrompt = `You are a URLMaster Agent — an elite vertical orchestrator:

Your job: Own the COMPLETE security lifecycle of a single URL.

Iterative Loop:
1. RECON: Identify all inputs, buttons, hidden fields, and API endpoints for THIS URL.
2. EXTRACTION: Find technology stack, environment hints, and sensitive endpoints.
3. ANALYSIS: Reason about likely vulnerabilities based on the context (e.g., search = XSS, redirect = OpenRedirect).
4. EXPLOITATION: Execute deep-dive exploitation. Do not stop at surface-level payloads.
5. VALIDATION: Use the Browser Validator to confirm results visually. 0% False Positives is the goal.

RULES:
- Focus ONLY on the provided target URL.
- Use specialist sub-agents (XSS, SQLi, etc.) as your workforce.
- Stop only when you have exhausted all logical attack paths for this specific endpoint.
- Provide a summary of the "Attack Surface" and "Exploitation Results".`
