package reporter

import (
	"fmt"
	"strings"
)

func buildSystemPrompt() string {
	return `You are an expert penetration testing report writer for Mirage, an autonomous AI-powered security platform. You produce clear, professional, and actionable pentest reports.

Output format rules:
- Use Markdown with ## for major sections and ### for subsections
- Use tables (pipe syntax) for structured data such as finding summaries and severity distributions
- Use **bold** for finding titles and key terms
- Keep executive language free of jargon; technical sections may use precise terminology
- Always close with a Remediation Roadmap section, grouping fixes into short-term (0-30 days), medium-term (31-90 days), and long-term (90+ days) phases

Quality standards:
- Quantify risk using the provided data (counts, severity, CVE IDs where present)
- Reference OWASP Top 10, MITRE ATT&CK techniques, or NIST controls where directly relevant
- Prioritise findings by business impact, not just CVSS score
- Provide concrete remediation guidance: library version, config flag, code pattern, or architectural change
- Never fabricate CVEs, exploit details, or findings not present in the provided data`
}

var templateSections = map[string]string{
	"executive": `Write an EXECUTIVE SUMMARY pentest report with the following sections:
## Executive Summary
## Overall Risk Rating
## Critical Findings
## Business Impact Assessment
## Strategic Recommendations
## Remediation Roadmap`,

	"technical": `Write a TECHNICAL PENTEST REPORT with the following sections:
## Scope & Methodology
## Findings by Severity
### Critical
### High
### Medium
### Low / Informational
## Attack Vector Analysis
## MITRE ATT&CK Coverage
## Technical Remediation Guide
## Remediation Roadmap`,

	"compliance": `Write a COMPLIANCE MAPPING REPORT with the following sections:
## Compliance Summary
## OWASP Top 10 Mapping
## Control Gap Analysis
## Policy Violations
## Findings Table (Markdown table: Finding | Severity | OWASP | Status)
## Remediation Roadmap`,

	"full": `Write a COMPREHENSIVE PENTEST REPORT with the following sections:
## Executive Summary
## Overall Risk Rating
## Scope & Methodology
## Findings by Severity
### Critical
### High
### Medium
### Low / Informational
## All Findings Summary (Markdown table)
## MITRE ATT&CK Coverage
## Attack Chain Analysis
## OWASP Top 10 Mapping
## Remediation Roadmap`,
}

func buildUserPrompt(req ReportRequest, data ReportData) string {
	var sb strings.Builder

	tmpl := req.Template
	if _, ok := templateSections[tmpl]; !ok {
		tmpl = "technical"
	}
	sb.WriteString(templateSections[tmpl])
	sb.WriteString("\n\n---\n\n## ASSESSMENT DATA\n\n")

	if data.Target != "" {
		sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", data.Target))
	}
	if data.FlowName != "" {
		sb.WriteString(fmt.Sprintf("**Engagement:** %s\n\n", data.FlowName))
	}
	if data.ScanDate != "" {
		sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", data.ScanDate))
	}

	// Severity table
	total := data.Critical + data.High + data.Medium + data.Low + data.Info
	sb.WriteString("### Severity Distribution\n\n")
	sb.WriteString("| Severity | Count | % of Total |\n")
	sb.WriteString("|----------|-------|------------|\n")
	pct := func(n int) string {
		if total == 0 {
			return "0%"
		}
		return fmt.Sprintf("%d%%", n*100/total)
	}
	sb.WriteString(fmt.Sprintf("| Critical | %d | %s |\n", data.Critical, pct(data.Critical)))
	sb.WriteString(fmt.Sprintf("| High     | %d | %s |\n", data.High, pct(data.High)))
	sb.WriteString(fmt.Sprintf("| Medium   | %d | %s |\n", data.Medium, pct(data.Medium)))
	sb.WriteString(fmt.Sprintf("| Low      | %d | %s |\n", data.Low, pct(data.Low)))
	sb.WriteString(fmt.Sprintf("| Info     | %d | %s |\n\n", data.Info, pct(data.Info)))

	if len(data.Findings) > 0 {
		sb.WriteString("### Findings List\n\n")
		limit := 60
		if len(data.Findings) < limit {
			limit = len(data.Findings)
		}
		for _, f := range data.Findings[:limit] {
			sb.WriteString(fmt.Sprintf("- **[%s]** %s (%s) — %s\n",
				strings.ToUpper(f.Severity), f.Title, f.Type, f.Target))
		}
		if len(data.Findings) > limit {
			sb.WriteString(fmt.Sprintf("- *…and %d additional findings*\n", len(data.Findings)-limit))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("*No findings recorded for this scope.*\n\n")
	}

	if req.IncludeThreatIntel && (data.TacticCount > 0 || data.TechniqueCount > 0) {
		sb.WriteString("### Threat Intelligence\n\n")
		sb.WriteString(fmt.Sprintf("- MITRE ATT&CK: **%d tactics**, **%d techniques** mapped\n", data.TacticCount, data.TechniqueCount))
		if data.ChainCount > 0 {
			sb.WriteString(fmt.Sprintf("- Attack chains identified: **%d**\n", data.ChainCount))
		}
		sb.WriteString("\n")
	}

	if req.IncludeMonitoring && data.MonitorCount > 0 {
		sb.WriteString("### Continuous Monitoring\n\n")
		sb.WriteString(fmt.Sprintf("- Active monitors: **%d**\n", data.MonitorCount))
		if data.NewSinceBaseline > 0 {
			sb.WriteString(fmt.Sprintf("- New findings since last baseline: **%d**\n", data.NewSinceBaseline))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\nGenerate the complete report now. Be thorough, professional, and grounded in the data provided above.")
	return sb.String()
}
