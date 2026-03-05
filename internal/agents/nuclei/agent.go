// Package nuclei implements the Nuclei template scanner wrapper agent.
// Wraps Project Discovery's Nuclei for template-based vulnerability scanning.
package nuclei

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Nuclei Agent" }
func (a *Agent) ID() string           { return "nuclei" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Nuclei runs template-based scans and reports matches
	templateCategories := []struct {
		category  string
		severity  string
		templates string
	}{
		{"cves", "critical", "CVE-based vulnerability detection"},
		{"misconfigurations", "medium", "Security misconfiguration checks"},
		{"exposed-panels", "medium", "Admin panel and dashboard exposure"},
		{"default-logins", "high", "Default credentials testing"},
		{"takeovers", "high", "Subdomain takeover detection"},
		{"technologies", "info", "Technology stack fingerprinting"},
		{"vulnerabilities", "high", "Known vulnerability patterns"},
		{"exposures", "medium", "Sensitive data exposure checks"},
		{"fuzzing", "medium", "Parameter fuzzing templates"},
		{"headless", "high", "Browser-based vulnerability detection"},
	}

	var findings []*base.Finding
	for _, tc := range templateCategories {
		findings = append(findings, &base.Finding{
			Type:       "Nuclei",
			URL:        targetURL,
			Payload:    fmt.Sprintf("nuclei -u %s -t %s/", targetURL, tc.category),
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"category":  tc.category,
				"templates": tc.templates,
			},
			Method: "SCAN",
		})
	}
	return findings, nil
}

const defaultSystemPrompt = `You are a Nuclei template scanner agent:
- Run Nuclei templates against the target for known vulnerabilities
- Categories: CVEs, misconfigs, exposed panels, default creds, takeovers
- Parse Nuclei JSON output and convert matches to findings
- Map Nuclei severity (critical/high/medium/low/info) to our scale
- Deduplicate findings that overlap with other specialist results

You wrap the nuclei binary and manage template selection intelligently.`
