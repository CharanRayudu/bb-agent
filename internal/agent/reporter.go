package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ReportGenerator creates professional pentest reports from flow data
type ReportGenerator struct{}

// NewReportGenerator creates a new report generator
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{}
}

// FindingReport represents a structured finding for the report
type FindingReport struct {
	Title       string
	Severity    string
	Endpoint    string
	Description string
	PoC         string
	Impact      string
	Remediation string
}

// GenerateReport creates a comprehensive markdown pentest report
func (rg *ReportGenerator) GenerateReport(
	target string,
	flowID uuid.UUID,
	duration time.Duration,
	reconSummary string,
	findings []*Finding,
	leads []string,
	exclusions []string,
	swarmResults string,
	pocResults string,
) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Penetration Test Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", target))
	sb.WriteString(fmt.Sprintf("**Flow ID:** `%s`\n", flowID.String()))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", formatReportDuration(duration)))

	// Executive Summary
	sb.WriteString("---\n\n## Executive Summary\n\n")

	criticalCount := countSeverity(findings, "critical")
	highCount := countSeverity(findings, "high")
	mediumCount := countSeverity(findings, "medium")
	lowCount := len(findings) - criticalCount - highCount - mediumCount

	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| [!] Critical | %d |\n", criticalCount))
	sb.WriteString(fmt.Sprintf("| [!] High | %d |\n", highCount))
	sb.WriteString(fmt.Sprintf("| [~] Medium | %d |\n", mediumCount))
	sb.WriteString(fmt.Sprintf("| [.] Low/Info | %d |\n", lowCount))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", len(findings)))

	if len(findings) == 0 {
		sb.WriteString("[OK] **No confirmed vulnerabilities were found during this assessment.**\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("[WARN] **%d vulnerabilities** were identified during this assessment, ", len(findings)))
		if criticalCount > 0 {
			sb.WriteString(fmt.Sprintf("including **%d critical** findings requiring immediate remediation.\n\n", criticalCount))
		} else if highCount > 0 {
			sb.WriteString(fmt.Sprintf("including **%d high-severity** findings.\n\n", highCount))
		} else {
			sb.WriteString("all at medium or lower severity.\n\n")
		}
	}

	// Methodology
	sb.WriteString("---\n\n## Methodology\n\n")
	sb.WriteString("This assessment was conducted using the **Mirage Autonomous Security Agent** with the following phases:\n\n")
	sb.WriteString("1. **Reconnaissance** -- Automated target profiling, technology fingerprinting, and attack surface mapping\n")
	sb.WriteString("2. **Planning** -- AI-driven analysis of recon data to identify high-value attack vectors\n")
	sb.WriteString("3. **Exploitation** -- Concurrent specialist agents testing for specific vulnerability classes\n")
	sb.WriteString("4. **Validation** -- PoC generation and finding confirmation with reproducible evidence\n")
	sb.WriteString("5. **Reporting** -- Automated report generation with remediation guidance\n\n")

	// Reconnaissance Summary
	sb.WriteString("---\n\n## Reconnaissance Summary\n\n")
	if reconSummary != "" {
		sb.WriteString(reconSummary + "\n\n")
	} else {
		sb.WriteString("No detailed recon summary available.\n\n")
	}

	// Detailed Findings
	sb.WriteString("---\n\n## Detailed Findings\n\n")
	if len(findings) > 0 {
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### Finding %d: %s\n\n", i+1, f.Type))
			sb.WriteString(fmt.Sprintf("**URL:** `%s`\n", f.URL))
			if f.Parameter != "" {
				sb.WriteString(fmt.Sprintf("**Parameter:** `%s`\n", f.Parameter))
			}
			sb.WriteString(fmt.Sprintf("**Severity:** %s\n", f.Severity))
			sb.WriteString(fmt.Sprintf("**Confidence:** %.2f\n\n", f.Confidence))
			if f.Payload != "" {
				sb.WriteString(fmt.Sprintf("**Payload:** `%s`\n\n", f.Payload))
			}
			if f.Evidence != nil {
				sb.WriteString("**Evidence:**\n```\n")
				for k, v := range f.Evidence {
					sb.WriteString(fmt.Sprintf("%s: %v\n", k, v))
				}
				sb.WriteString("```\n\n")
			}
			sb.WriteString("---\n\n")
		}
	} else {
		sb.WriteString("No vulnerabilities were confirmed during this assessment.\n\n")
	}

	// Exploitation Results
	if swarmResults != "" {
		sb.WriteString("---\n\n## Exploitation Details\n\n")
		sb.WriteString(swarmResults + "\n\n")
	}

	// PoC Evidence
	if pocResults != "" {
		sb.WriteString("---\n\n## Proof of Concept (PoC) Evidence\n\n")
		sb.WriteString(pocResults + "\n\n")
	}

	// Recon Leads (for future investigation)
	if len(leads) > 0 {
		sb.WriteString("---\n\n## Additional Leads (Unconfirmed)\n\n")
		sb.WriteString("The following items were identified during reconnaissance but not confirmed as vulnerabilities:\n\n")
		for i, l := range leads {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, l))
		}
		sb.WriteString("\n")
	}

	// Excluded / Dead Ends
	if len(exclusions) > 0 {
		sb.WriteString("---\n\n## Excluded / Dead Ends\n\n")
		for i, e := range exclusions {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, e))
		}
		sb.WriteString("\n")
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString("*Report generated by Mirage Autonomous Security Agent*\n")
	sb.WriteString(fmt.Sprintf("*Assessment completed: %s*\n", time.Now().Format(time.RFC3339)))

	return sb.String()
}

// countSeverity counts findings of a specific severity
func countSeverity(findings []*Finding, severity string) int {
	count := 0
	targetSev := strings.ToLower(severity)
	for _, f := range findings {
		if strings.ToLower(f.Severity) == targetSev {
			count++
		}
	}
	return count
}

func formatReportDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes %d seconds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d hours %d minutes", int(d.Hours()), int(d.Minutes())%60)
}
