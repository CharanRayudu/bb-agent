// Package apisecurity implements the API Security specialist agent.
// Tests for broken authentication, broken authorization, rate limiting,
// mass assignment, and other OWASP API Top 10 vulnerabilities.
package apisecurity

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "API Security Agent" }
func (a *Agent) ID() string           { return "apisecurity" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, tc := range testCases {
		findings = append(findings, &base.Finding{
			Type:       "API Security",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"category": tc.category, "owasp_api": tc.owaspRef},
			Method:     tc.method,
		})
	}
	return findings, nil
}

type apiTestCase struct {
	payload  string
	category string
	owaspRef string
	severity string
	method   string
}

var testCases = []apiTestCase{
	// BOLA (Broken Object Level Authorization) — OWASP API #1
	{"Swap user IDs in resource paths (/api/users/2 → /api/users/1)", "BOLA", "API1", "high", "GET"},
	// Broken Authentication — OWASP API #2
	{"Send request without Authorization header", "Broken Auth", "API2", "critical", "GET"},
	{"Send expired/malformed JWT token", "Broken Auth", "API2", "high", "GET"},
	// Excessive Data Exposure — OWASP API #3
	{"Check response for sensitive fields (password, ssn, secret)", "Data Exposure", "API3", "high", "GET"},
	// Lack of Rate Limiting — OWASP API #4
	{"Send 100+ requests in rapid succession", "Rate Limiting", "API4", "medium", "GET"},
	// BFLA (Broken Function Level Authorization) — OWASP API #5
	{"Switch GET to PUT/DELETE on read-only endpoints", "BFLA", "API5", "high", "PUT"},
	{"Access /api/admin/* as regular user", "BFLA", "API5", "critical", "GET"},
	// Mass Assignment — OWASP API #6
	{`{"role":"admin","is_admin":true}`, "Mass Assignment", "API6", "high", "PUT"},
	// Security Misconfiguration — OWASP API #7
	{"Check CORS: Origin: https://evil.com", "CORS Misconfig", "API7", "medium", "GET"},
	{"Check verbose error messages with invalid input", "Error Disclosure", "API7", "low", "GET"},
	// Injection — OWASP API #8
	{"GraphQL introspection query: {__schema{types{name}}}", "GraphQL Introspection", "API8", "medium", "POST"},
	{`{"query":"{ users { id password } }"}`, "GraphQL Data Leak", "API8", "high", "POST"},
	// Improper Asset Management — OWASP API #9
	{"Probe /api/v1/ vs /api/v2/ for deprecated endpoints", "Asset Management", "API9", "medium", "GET"},
	// Insufficient Logging — OWASP API #10
	{"Inject malicious activity and check for alerting", "Logging", "API10", "low", "POST"},
}

const defaultSystemPrompt = `You are an elite API Security specialist covering the OWASP API Top 10:
1. BOLA — Test object-level authorization by swapping IDs
2. Broken Auth — Test without tokens, with expired tokens
3. Data Exposure — Check responses for leaked sensitive fields
4. Rate Limiting — Test for brute-force feasibility
5. BFLA — Test function-level auth (admin endpoints, method switching)
6. Mass Assignment — Inject extra fields (role, is_admin)
7. CORS/Misconfig — Check CORS headers, verbose errors
8. Injection — GraphQL introspection, query manipulation
9. Asset Management — Find deprecated API versions
10. Logging — Verify security events are logged`
