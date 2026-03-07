// Package reporting implements the AI-powered Report Generation agent.
// Generates technical and executive reports from scan findings.
// Implements the Reporting capabilities.
package reporting

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Reporting Agent" }
func (a *Agent) ID() string           { return "reporting" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// The reporting agent produces report sections as findings
	sections := []struct {
		section string
		detail  string
	}{
		{"executive_summary", "High-level overview for management: scope, risk rating, key findings"},
		{"technical_summary", "Detailed technical findings with payloads, evidence, and reproduction steps"},
		{"vulnerability_details", "Per-finding breakdown: description, impact, PoC, remediation"},
		{"risk_matrix", "CVSS scoring and risk prioritization matrix"},
		{"remediation_plan", "Prioritized remediation steps with effort estimates"},
		{"methodology", "Testing methodology and tools used"},
		{"scope", "Target scope, in-scope and out-of-scope items"},
		{"owasp_mapping", "Map findings to OWASP Top 10 / CWE categories"},
		{"compliance_impact", "Impact on compliance frameworks (PCI-DSS, SOC2, HIPAA)"},
	}

	var findings []*base.Finding
	for _, s := range sections {
		findings = append(findings, &base.Finding{
			Type:       "Report",
			URL:        targetURL,
			Payload:    s.detail,
			Severity:   "info",
			Confidence: 1.0,
			Evidence:   map[string]interface{}{"section": s.section},
			Method:     "REPORT",
		})
	}
	return findings, nil
}

const defaultSystemPrompt = `You are an AI-powered Penetration Test Report Generator:

Generate comprehensive reports with these sections:
1. EXECUTIVE SUMMARY -- Risk overview for management (no technical jargon)
2. TECHNICAL SUMMARY -- Detailed findings for the security team
3. VULNERABILITY DETAILS -- Per-finding: description, impact, PoC, remediation
4. RISK MATRIX -- CVSS scores and prioritization
5. REMEDIATION PLAN -- Prioritized fixes with effort estimates
6. METHODOLOGY -- Testing approach and tools used
7. OWASP MAPPING -- Map each finding to OWASP Top 10 / CWE
8. COMPLIANCE -- Impact on PCI-DSS, SOC2, HIPAA if applicable

Format: Markdown with tables, severity badges, and code blocks for payloads.`
