package agent

import (
	"fmt"
	"strings"
	"time"
)

// GenerateHTMLReport creates a print-optimized HTML report (browser-printable as PDF).
func GenerateHTMLReport(target, flowID, duration string, findings []*Finding) string {
	var sb strings.Builder

	criticalCount := countSeverity(findings, "critical")
	highCount := countSeverity(findings, "high")
	mediumCount := countSeverity(findings, "medium")
	lowCount := len(findings) - criticalCount - highCount - mediumCount
	if lowCount < 0 {
		lowCount = 0
	}

	reportDate := time.Now().Format("January 02, 2006")
	reportTime := time.Now().Format("15:04:05 MST")

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mirage Pentest Report - ` + htmlEscape(target) + `</title>
<style>
/* ===== Base ===== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  font-size: 13px;
  line-height: 1.6;
  color: #1a1a2e;
  background: #f8f9fa;
}
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }

/* ===== Print ===== */
@media print {
  body { background: #fff; font-size: 11px; }
  .no-print { display: none !important; }
  .page-break { page-break-before: always; }
  .finding-card { page-break-inside: avoid; }
  header { background: #1a1a2e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .severity-badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .chart-bar { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .section { box-shadow: none; border: 1px solid #ddd; }
}

/* ===== Layout ===== */
.container { max-width: 1100px; margin: 0 auto; padding: 0 20px 40px; }

header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
  color: #fff;
  padding: 40px 40px 30px;
  margin-bottom: 30px;
}
header .logo { font-size: 28px; font-weight: 700; letter-spacing: 3px; color: #e94560; }
header .subtitle { font-size: 13px; color: #a0aec0; margin-top: 4px; }
header .meta { margin-top: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
header .meta-item { background: rgba(255,255,255,0.07); border-radius: 8px; padding: 10px 14px; }
header .meta-item .label { font-size: 10px; color: #a0aec0; text-transform: uppercase; letter-spacing: 1px; }
header .meta-item .value { font-size: 14px; font-weight: 600; color: #e2e8f0; margin-top: 2px; word-break: break-all; }

.section {
  background: #fff;
  border-radius: 10px;
  padding: 28px 32px;
  margin-bottom: 24px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.07);
}
.section-title {
  font-size: 18px;
  font-weight: 700;
  color: #1a1a2e;
  border-bottom: 2px solid #e94560;
  padding-bottom: 10px;
  margin-bottom: 20px;
}

/* ===== Severity colours ===== */
.sev-critical { color: #fff; background: #c0392b; }
.sev-high     { color: #fff; background: #e67e22; }
.sev-medium   { color: #fff; background: #f39c12; }
.sev-low      { color: #fff; background: #27ae60; }
.sev-info     { color: #fff; background: #3498db; }

.severity-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* ===== Summary table ===== */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.summary-card {
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  color: #fff;
}
.summary-card .count { font-size: 36px; font-weight: 800; line-height: 1; }
.summary-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; opacity: 0.85; }
.sc-critical { background: linear-gradient(135deg, #c0392b, #e74c3c); }
.sc-high     { background: linear-gradient(135deg, #d35400, #e67e22); }
.sc-medium   { background: linear-gradient(135deg, #d39e00, #f39c12); }
.sc-low      { background: linear-gradient(135deg, #1e8449, #27ae60); }
.sc-total    { background: linear-gradient(135deg, #1a1a2e, #0f3460); }

/* ===== Severity chart (CSS bars) ===== */
.chart { margin: 20px 0; }
.chart-row { display: flex; align-items: center; margin-bottom: 10px; gap: 12px; }
.chart-label { width: 70px; font-size: 12px; font-weight: 600; text-align: right; }
.chart-track { flex: 1; background: #f0f0f0; border-radius: 4px; height: 22px; overflow: hidden; }
.chart-bar { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px;
             font-size: 11px; font-weight: 700; color: #fff; min-width: 2px; transition: width 0.3s; }
.chart-count { width: 28px; font-size: 12px; font-weight: 700; color: #555; }

/* ===== Findings table ===== */
.findings-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.findings-table th {
  background: #1a1a2e;
  color: #e2e8f0;
  padding: 10px 12px;
  text-align: left;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.findings-table td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
.findings-table tr:hover td { background: #f8f9fa; }
.url-cell { font-family: monospace; font-size: 11px; word-break: break-all; max-width: 280px; }
.cvss-score { font-weight: 700; }
.cvss-critical { color: #c0392b; }
.cvss-high     { color: #e67e22; }
.cvss-medium   { color: #f39c12; }
.cvss-low      { color: #27ae60; }

/* ===== Finding cards ===== */
.finding-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  margin-bottom: 20px;
  overflow: hidden;
}
.finding-header {
  padding: 14px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid #e2e8f0;
}
.finding-header.fh-critical { background: #fdeded; }
.finding-header.fh-high     { background: #fef3e2; }
.finding-header.fh-medium   { background: #fef9e7; }
.finding-header.fh-low      { background: #eafaf1; }
.finding-header.fh-info     { background: #ebf5fb; }
.finding-title { font-size: 15px; font-weight: 700; flex: 1; }
.finding-body { padding: 18px 20px; }
.finding-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-bottom: 14px; }
.meta-field { }
.meta-field .key { font-size: 10px; color: #718096; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
.meta-field .val { font-size: 12px; color: #2d3748; margin-top: 1px; word-break: break-all; }
.meta-field .val code { background: #f0f0f0; padding: 1px 5px; border-radius: 3px; font-size: 11px; font-family: monospace; }

/* ===== Code / evidence ===== */
.evidence-block {
  background: #1e2433;
  color: #e2e8f0;
  padding: 12px 16px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 11px;
  line-height: 1.5;
  overflow-x: auto;
  margin: 10px 0;
  white-space: pre-wrap;
  word-break: break-all;
}

/* ===== Compliance tags ===== */
.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 600;
}
.tag-cwe   { background: #fde8e8; color: #c0392b; }
.tag-owasp { background: #e8f4fd; color: #1a6fa8; }
.tag-nist  { background: #e8fdf5; color: #1a7a50; }
.tag-pci   { background: #fdf3e8; color: #a06000; }

/* ===== Remediation ===== */
.remediation-section { margin-top: 14px; }
.remediation-title { font-size: 12px; font-weight: 700; color: #2d3748; margin-bottom: 8px; }
.remediation-steps { padding-left: 18px; }
.remediation-steps li { margin-bottom: 5px; font-size: 12px; color: #4a5568; }
.references { margin-top: 8px; }
.references a { font-size: 11px; color: #0066cc; }

/* ===== Business impact ===== */
.impact-bar-container { background: #f0f0f0; border-radius: 6px; height: 14px; margin: 6px 0 4px; overflow: hidden; }
.impact-bar { height: 100%; border-radius: 6px; }
.impact-high   { background: linear-gradient(90deg, #e74c3c, #c0392b); }
.impact-medium { background: linear-gradient(90deg, #e67e22, #d35400); }
.impact-low    { background: linear-gradient(90deg, #f1c40f, #f39c12); }

/* ===== Footer ===== */
footer {
  text-align: center;
  font-size: 11px;
  color: #a0aec0;
  padding: 20px;
  border-top: 1px solid #e2e8f0;
  margin-top: 40px;
}
</style>
</head>
<body>
`)

	// Header
	sb.WriteString(`<header>
  <div class="logo">MIRAGE</div>
  <div class="subtitle">Autonomous Penetration Testing Report</div>
  <div class="meta">
    <div class="meta-item"><div class="label">Target</div><div class="value">` + htmlEscape(target) + `</div></div>
    <div class="meta-item"><div class="label">Flow ID</div><div class="value">` + htmlEscape(flowID) + `</div></div>
    <div class="meta-item"><div class="label">Date</div><div class="value">` + reportDate + `</div></div>
    <div class="meta-item"><div class="label">Time</div><div class="value">` + reportTime + `</div></div>
    <div class="meta-item"><div class="label">Duration</div><div class="value">` + htmlEscape(duration) + `</div></div>
  </div>
</header>
<div class="container">
`)

	// Executive Summary
	sb.WriteString(`<div class="section">
  <div class="section-title">Executive Summary</div>
`)
	sb.WriteString(fmt.Sprintf(`  <div class="summary-grid">
    <div class="summary-card sc-critical"><div class="count">%d</div><div class="label">Critical</div></div>
    <div class="summary-card sc-high"><div class="count">%d</div><div class="label">High</div></div>
    <div class="summary-card sc-medium"><div class="count">%d</div><div class="label">Medium</div></div>
    <div class="summary-card sc-low"><div class="count">%d</div><div class="label">Low / Info</div></div>
    <div class="summary-card sc-total"><div class="count">%d</div><div class="label">Total</div></div>
  </div>
`, criticalCount, highCount, mediumCount, lowCount, len(findings)))

	// CSS bar chart
	total := len(findings)
	if total == 0 {
		total = 1
	}
	sb.WriteString(`  <div class="chart">`)
	type chartRow struct {
		label string
		count int
		cls   string
	}
	chartRows := []chartRow{
		{"Critical", criticalCount, "sev-critical"},
		{"High", highCount, "sev-high"},
		{"Medium", mediumCount, "sev-medium"},
		{"Low", lowCount, "sev-low"},
	}
	for _, cr := range chartRows {
		pct := cr.count * 100 / total
		sb.WriteString(fmt.Sprintf(`
    <div class="chart-row">
      <div class="chart-label">%s</div>
      <div class="chart-track"><div class="chart-bar %s" style="width:%d%%">%s</div></div>
      <div class="chart-count">%d</div>
    </div>`, cr.label, cr.cls, pct, func() string {
			if cr.count > 0 {
				return fmt.Sprintf("%d", cr.count)
			}
			return ""
		}(), cr.count))
	}
	sb.WriteString("\n  </div>\n")

	if len(findings) == 0 {
		sb.WriteString(`  <p style="color:#27ae60;font-weight:600;">No confirmed vulnerabilities were identified during this assessment.</p>`)
	} else if criticalCount > 0 {
		sb.WriteString(fmt.Sprintf(`  <p><strong>%d vulnerabilities</strong> were identified, including <strong style="color:#c0392b">%d critical</strong> findings requiring immediate remediation.</p>`, len(findings), criticalCount))
	} else if highCount > 0 {
		sb.WriteString(fmt.Sprintf(`  <p><strong>%d vulnerabilities</strong> were identified, including <strong style="color:#e67e22">%d high-severity</strong> findings.</p>`, len(findings), highCount))
	} else {
		sb.WriteString(fmt.Sprintf(`  <p><strong>%d vulnerabilities</strong> were identified, all at medium or lower severity.</p>`, len(findings)))
	}
	sb.WriteString("\n</div>\n")

	// Findings Overview Table
	if len(findings) > 0 {
		sb.WriteString(`<div class="section">
  <div class="section-title">Findings Overview</div>
  <table class="findings-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Vulnerability</th>
        <th>URL</th>
        <th>Parameter</th>
        <th>Severity</th>
        <th>CVSS</th>
        <th>Confidence</th>
      </tr>
    </thead>
    <tbody>
`)
		for i, f := range findings {
			cvss := ScoreFinding(f)
			sev := strings.ToLower(strings.TrimSpace(f.Severity))
			cvssClass := "cvss-" + sev
			sb.WriteString(fmt.Sprintf(`      <tr>
        <td>%d</td>
        <td><strong>%s</strong></td>
        <td class="url-cell"><code>%s</code></td>
        <td>%s</td>
        <td><span class="severity-badge sev-%s">%s</span></td>
        <td class="cvss-score %s">%.1f</td>
        <td>%.0f%%</td>
      </tr>
`, i+1, htmlEscape(f.Type), htmlEscape(f.URL), htmlEscape(f.Parameter), sev, strings.ToUpper(sev), cvssClass, cvss.Score, f.Confidence*100))
		}
		sb.WriteString("    </tbody>\n  </table>\n</div>\n")
	}

	// Detailed Findings
	if len(findings) > 0 {
		sb.WriteString(`<div class="section page-break">
  <div class="section-title">Detailed Findings</div>
`)
		for i, f := range findings {
			cvss := ScoreFinding(f)
			rem := RemediationFor(f.Type)
			comp := ComplianceTags(f.Type)
			impact := BusinessImpactScore(f)
			sev := strings.ToLower(strings.TrimSpace(f.Severity))

			sb.WriteString(fmt.Sprintf(`  <div class="finding-card">
    <div class="finding-header fh-%s">
      <span class="severity-badge sev-%s">%s</span>
      <span class="finding-title">%d. %s</span>
      <span style="font-size:12px;color:#718096;">CVSS %.1f</span>
    </div>
    <div class="finding-body">
`, sev, sev, strings.ToUpper(sev), i+1, htmlEscape(f.Type), cvss.Score))

			// Meta fields
			sb.WriteString(`      <div class="finding-meta">`)
			sb.WriteString(fmt.Sprintf(`
        <div class="meta-field"><div class="key">URL</div><div class="val"><code>%s</code></div></div>`, htmlEscape(f.URL)))
			if f.Parameter != "" {
				sb.WriteString(fmt.Sprintf(`
        <div class="meta-field"><div class="key">Parameter</div><div class="val"><code>%s</code></div></div>`, htmlEscape(f.Parameter)))
			}
			if f.Method != "" {
				sb.WriteString(fmt.Sprintf(`
        <div class="meta-field"><div class="key">Method</div><div class="val">%s</div></div>`, htmlEscape(f.Method)))
			}
			sb.WriteString(fmt.Sprintf(`
        <div class="meta-field"><div class="key">CVSS Vector</div><div class="val"><code>%s</code></div></div>
        <div class="meta-field"><div class="key">Exploitability</div><div class="val">%s</div></div>
        <div class="meta-field"><div class="key">Confidence</div><div class="val">%.0f%%</div></div>`,
				htmlEscape(cvss.Vector), htmlEscape(cvss.Exploitable), f.Confidence*100))
			sb.WriteString("\n      </div>\n")

			// Payload
			if f.Payload != "" {
				sb.WriteString(fmt.Sprintf(`      <div style="margin-bottom:12px;"><div class="key" style="font-size:10px;color:#718096;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Payload</div><div class="evidence-block">%s</div></div>`, htmlEscape(f.Payload)))
			}

			// Evidence
			if len(f.Evidence) > 0 {
				sb.WriteString(`      <div style="margin-bottom:12px;"><div class="key" style="font-size:10px;color:#718096;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Evidence</div><div class="evidence-block">`)
				for k, v := range f.Evidence {
					sb.WriteString(fmt.Sprintf("%s: %v\n", htmlEscape(k), htmlEscape(fmt.Sprintf("%v", v))))
				}
				sb.WriteString("</div></div>\n")
			}

			// Business Impact
			impactBarClass := "impact-low"
			if impact.Score >= 8 {
				impactBarClass = "impact-high"
			} else if impact.Score >= 5 {
				impactBarClass = "impact-medium"
			}
			impactPct := int(impact.Score * 10)
			sb.WriteString(fmt.Sprintf(`      <div style="margin-bottom:14px;">
        <div class="remediation-title">Business Impact (Score: %.1f/10 — %s)</div>
        <div class="impact-bar-container"><div class="impact-bar %s" style="width:%d%%"></div></div>
        <p style="font-size:12px;color:#4a5568;margin-top:4px;">%s</p>
        <div style="margin-top:6px;font-size:11px;color:#718096;"><strong>Affected assets:</strong> %s</div>
      </div>
`, impact.Score, htmlEscape(impact.Category), impactBarClass, impactPct, htmlEscape(impact.Explanation), htmlEscape(strings.Join(impact.AffectedAssets, ", "))))

			// Compliance tags
			sb.WriteString(`      <div style="margin-bottom:14px;">
        <div class="remediation-title">Compliance Mapping</div>
        <div class="tag-list">`)
			for _, cwe := range comp.CWE {
				sb.WriteString(fmt.Sprintf(`<span class="tag tag-cwe">%s</span>`, htmlEscape(cwe)))
			}
			for _, owasp := range comp.OWASP {
				sb.WriteString(fmt.Sprintf(`<span class="tag tag-owasp">%s</span>`, htmlEscape(owasp)))
			}
			for _, nist := range comp.NIST {
				sb.WriteString(fmt.Sprintf(`<span class="tag tag-nist">NIST %s</span>`, htmlEscape(nist)))
			}
			for _, pci := range comp.PCI_DSS {
				sb.WriteString(fmt.Sprintf(`<span class="tag tag-pci">PCI DSS %s</span>`, htmlEscape(pci)))
			}
			sb.WriteString("</div>\n      </div>\n")

			// Remediation
			sb.WriteString(fmt.Sprintf(`      <div class="remediation-section">
        <div class="remediation-title">Remediation <span style="font-size:11px;color:#e67e22;font-weight:400;">[Priority: %s]</span></div>
        <p style="font-size:12px;color:#4a5568;margin-bottom:8px;">%s</p>
        <ol class="remediation-steps">
`, htmlEscape(rem.Priority), htmlEscape(rem.Summary)))
			for _, step := range rem.Steps {
				sb.WriteString(fmt.Sprintf("          <li>%s</li>\n", htmlEscape(step)))
			}
			sb.WriteString("        </ol>\n")
			if len(rem.References) > 0 {
				sb.WriteString(`        <div class="references" style="margin-top:8px;">`)
				for _, ref := range rem.References {
					sb.WriteString(fmt.Sprintf(`<a href="%s" target="_blank">%s</a> &nbsp;`, htmlEscape(ref), htmlEscape(ref)))
				}
				sb.WriteString("</div>\n")
			}
			sb.WriteString("      </div>\n")

			sb.WriteString("    </div>\n  </div>\n")
		}
		sb.WriteString("</div>\n")
	}

	// Compliance Summary Section
	if len(findings) > 0 {
		sb.WriteString(`<div class="section">
  <div class="section-title">Compliance Mapping Summary</div>
  <table class="findings-table">
    <thead>
      <tr><th>Vulnerability</th><th>CWE</th><th>OWASP Top 10 2021</th><th>NIST 800-53</th><th>PCI DSS</th></tr>
    </thead>
    <tbody>
`)
		seen := make(map[string]bool)
		for _, f := range findings {
			if seen[f.Type] {
				continue
			}
			seen[f.Type] = true
			comp := ComplianceTags(f.Type)
			sb.WriteString(fmt.Sprintf("      <tr>\n        <td><strong>%s</strong></td>\n", htmlEscape(f.Type)))
			sb.WriteString(fmt.Sprintf("        <td>%s</td>\n", htmlEscape(strings.Join(comp.CWE, ", "))))
			sb.WriteString(fmt.Sprintf("        <td>%s</td>\n", htmlEscape(strings.Join(comp.OWASP, "; "))))
			sb.WriteString(fmt.Sprintf("        <td>%s</td>\n", htmlEscape(strings.Join(comp.NIST, ", "))))
			sb.WriteString(fmt.Sprintf("        <td>%s</td>\n      </tr>\n", htmlEscape(strings.Join(comp.PCI_DSS, ", "))))
		}
		sb.WriteString("    </tbody>\n  </table>\n</div>\n")
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`
<footer>
  <p>Generated by <strong>Mirage Autonomous Security Agent</strong> &mdash; %s</p>
  <p style="margin-top:4px;">This report is confidential. Handle according to your organization's data classification policy.</p>
</footer>
</div>
</body>
</html>
`, time.Now().Format(time.RFC3339)))

	return sb.String()
}

// htmlEscape escapes special HTML characters.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
