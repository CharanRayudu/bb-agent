// Package threatintel maps vulnerability findings to MITRE ATT&CK techniques,
// chains them into kill-path graphs, enriches with EPSS/KEV scores, and
// produces a risk-prioritized remediation list.
//
// ATT&CK coverage:
//   - 14 tactics from TA0001 (Initial Access) through TA0011 (Exfiltration)
//   - 60+ technique mappings across all Mirage finding types
//   - Subtechnique support (T1190, T1059.004, T1552.001, …)
//
// Attack chains:
//   - Directed graph: 35 "enables" edges between finding types
//   - Chain scoring: depth × severity-weight × confidence
//   - Critical kill paths: SSRF→IMDS→Cloud Creds, XSS→Session→IDOR, SQLi→RCE
//
// Risk scoring:
//   - Composite: CVSS(30%) + EPSS×100(25%) + KEV bonus(15%) + chain depth(20%) + severity(10%)
//   - Normalised 0–100; critical threshold ≥ 75
package threatintel
