// Package dastysast implements the hybrid DAST/SAST analysis agent.
// Probes URLs, classifies input types, detects tech stack, and
// identifies injection points for specialist agents.
// Implements the DASTySAST strategy.
package dastysast

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "DASTySAST Agent" }
func (a *Agent) ID() string           { return "dastysast" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// DASTySAST probes each URL and produces analysis findings
	analyses := []struct {
		task     string
		category string
		detail   string
	}{
		{"input_classification", "DAST", "Classify all input vectors (query params, POST body, headers, cookies)"},
		{"reflection_analysis", "DAST", "Send probe strings and check for reflection in response"},
		{"error_fingerprint", "DAST", "Send malformed input to trigger error messages for tech fingerprinting"},
		{"form_detection", "DAST", "Detect and catalog all HTML forms (login, search, upload, contact)"},
		{"header_analysis", "DAST", "Analyze response headers for security misconfigurations"},
		{"cookie_analysis", "DAST", "Check cookie flags (Secure, HttpOnly, SameSite, Domain, Path)"},
		{"js_source_analysis", "SAST", "Static analysis of inline/external JS for dangerous sinks (eval, innerHTML)"},
		{"api_endpoint_detection", "DAST", "Identify REST/GraphQL API endpoints from JavaScript and responses"},
		{"csp_analysis", "DAST", "Parse and evaluate Content-Security-Policy for bypasses"},
		{"cors_analysis", "DAST", "Test CORS configuration with various Origin headers"},
		{"tech_stack_detection", "DAST", "Identify server, framework, and libraries from headers/response"},
	}

	var findings []*base.Finding
	for _, a := range analyses {
		findings = append(findings, &base.Finding{
			Type:       "Analysis",
			URL:        targetURL,
			Payload:    a.detail,
			Severity:   "info",
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"task": a.task, "category": a.category},
			Method:     "ANALYSIS",
		})
	}
	return findings, nil
}

const defaultSystemPrompt = `You are a hybrid DAST/SAST analysis agent responsible for:

DAST (Dynamic Analysis):
- Probe each URL with harmless test strings to map input vectors
- Classify injection points (query params, POST body, headers, cookies)
- Check for input reflection in responses (XSS candidates)
- Trigger error messages for technology fingerprinting
- Analyze security headers (CSP, CORS, X-Frame-Options, HSTS)

SAST (Static Analysis):
- Parse JavaScript for dangerous sinks (eval, innerHTML, document.write)
- Identify API endpoints from JS source code
- Check for hardcoded secrets or API keys in client-side code

Your output feeds the Strategy/Thinking phase for specialist routing.`
