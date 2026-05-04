// Package compliance maps vulnerability findings to compliance framework controls.
//
// Supported frameworks:
//   - OWASP Top 10 (2021)
//   - PCI-DSS v4.0
//   - ISO/IEC 27001:2022 (Annex A)
//   - SOC 2 Trust Service Criteria (TSC)
//   - NIST SP 800-53 Rev 5
//   - CWE (Common Weakness Enumeration)
package compliance

import "strings"

// Control represents a single compliance control requirement.
type Control struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	Description string `json:"description"`
}

// FindingMapping holds all compliance controls triggered by a finding type.
type FindingMapping struct {
	FindingType string    `json:"finding_type"`
	CWEs        []string  `json:"cwes"`
	Controls    []Control `json:"controls"`
}

// frameworkControls defines compliance control mappings per finding type.
var frameworkControls = map[string]FindingMapping{
	"XSS": {
		CWEs: []string{"CWE-79"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Software engineering practices to prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical and physical access controls"},
			{Framework: "NIST", ControlID: "SI-10", ControlName: "Information Input Validation"},
		},
	},
	"SQLi": {
		CWEs: []string{"CWE-89"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities in bespoke and custom software"},
			{Framework: "PCI-DSS", ControlID: "6.3.2", ControlName: "An inventory of bespoke and custom software"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "SOC2", ControlID: "CC7.1", ControlName: "Detection and monitoring procedures"},
			{Framework: "NIST", ControlID: "SI-10", ControlName: "Information Input Validation"},
		},
	},
	"SSRF": {
		CWEs: []string{"CWE-918"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A10:2021", ControlName: "Server-Side Request Forgery"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.20", ControlName: "Networks security"},
			{Framework: "SOC2", ControlID: "CC6.6", ControlName: "Logical access security measures"},
			{Framework: "NIST", ControlID: "SC-7", ControlName: "Boundary Protection"},
		},
	},
	"RCE": {
		CWEs: []string{"CWE-78", "CWE-94", "CWE-502"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "PCI-DSS", ControlID: "6.4.1", ControlName: "For public-facing web applications, address new threats"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "SOC2", ControlID: "CC7.2", ControlName: "Monitor system components for anomalous behavior"},
			{Framework: "NIST", ControlID: "SI-3", ControlName: "Malicious Code Protection"},
		},
	},
	"LFI": {
		CWEs: []string{"CWE-22"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A01:2021", ControlName: "Broken Access Control"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.3", ControlName: "Information access restriction"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical and physical access controls"},
			{Framework: "NIST", ControlID: "AC-3", ControlName: "Access Enforcement"},
		},
	},
	"IDOR": {
		CWEs: []string{"CWE-639"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A01:2021", ControlName: "Broken Access Control"},
			{Framework: "PCI-DSS", ControlID: "7.2", ControlName: "Access to system components is defined appropriately"},
			{Framework: "ISO27001", ControlID: "A.8.3", ControlName: "Information access restriction"},
			{Framework: "SOC2", ControlID: "CC6.3", ControlName: "Role-based access control"},
			{Framework: "NIST", ControlID: "AC-4", ControlName: "Information Flow Enforcement"},
		},
	},
	"JWT": {
		CWEs: []string{"CWE-347", "CWE-345"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A02:2021", ControlName: "Cryptographic Failures"},
			{Framework: "PCI-DSS", ControlID: "8.6", ControlName: "System/application accounts are managed"},
			{Framework: "ISO27001", ControlID: "A.8.24", ControlName: "Use of cryptography"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical access security"},
			{Framework: "NIST", ControlID: "IA-5", ControlName: "Authenticator Management"},
		},
	},
	"SSTI": {
		CWEs: []string{"CWE-94"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "SOC2", ControlID: "CC7.1", ControlName: "Detection and monitoring"},
			{Framework: "NIST", ControlID: "SI-10", ControlName: "Information Input Validation"},
		},
	},
	"XXE": {
		CWEs: []string{"CWE-611"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A05:2021", ControlName: "Security Misconfiguration"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "NIST", ControlID: "SI-10", ControlName: "Information Input Validation"},
		},
	},
	"CORS": {
		CWEs: []string{"CWE-942"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A05:2021", ControlName: "Security Misconfiguration"},
			{Framework: "PCI-DSS", ControlID: "6.2.4", ControlName: "Prevent common vulnerabilities"},
			{Framework: "ISO27001", ControlID: "A.8.20", ControlName: "Networks security"},
			{Framework: "SOC2", ControlID: "CC6.6", ControlName: "Logical access security measures against threats from outside"},
			{Framework: "NIST", ControlID: "SC-8", ControlName: "Transmission Confidentiality and Integrity"},
		},
	},
	// Cloud security
	"CLOUD_AWS_IMDS_EXPOSED": {
		CWEs: []string{"CWE-306", "CWE-284"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A05:2021", ControlName: "Security Misconfiguration"},
			{Framework: "PCI-DSS", ControlID: "2.2", ControlName: "System components are configured and managed securely"},
			{Framework: "ISO27001", ControlID: "A.8.9", ControlName: "Configuration management"},
			{Framework: "SOC2", ControlID: "CC6.6", ControlName: "Logical access security measures"},
			{Framework: "NIST", ControlID: "CM-6", ControlName: "Configuration Settings"},
		},
	},
	"CLOUD_S3_PUBLIC_BUCKET": {
		CWEs: []string{"CWE-284"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A01:2021", ControlName: "Broken Access Control"},
			{Framework: "PCI-DSS", ControlID: "7.2", ControlName: "Access to system components is defined appropriately"},
			{Framework: "ISO27001", ControlID: "A.5.15", ControlName: "Access control"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical and physical access controls"},
			{Framework: "NIST", ControlID: "AC-3", ControlName: "Access Enforcement"},
		},
	},
	"CLOUD_CREDENTIAL_LEAK": {
		CWEs: []string{"CWE-798", "CWE-259"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A02:2021", ControlName: "Cryptographic Failures"},
			{Framework: "PCI-DSS", ControlID: "8.3", ControlName: "User identification and related accounts are managed"},
			{Framework: "ISO27001", ControlID: "A.8.13", ControlName: "Information backup"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical and physical access controls"},
			{Framework: "NIST", ControlID: "IA-5", ControlName: "Authenticator Management"},
		},
	},
	// LLM/AI security
	"LLM_PROMPT_INJECTION": {
		CWEs: []string{"CWE-77", "CWE-94"},
		Controls: []Control{
			{Framework: "OWASP-LLM", ControlID: "LLM01:2025", ControlName: "Prompt Injection"},
			{Framework: "NIST-AI", ControlID: "GV-6.1", ControlName: "Policies and procedures for AI risk management"},
			{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding"},
			{Framework: "SOC2", ControlID: "CC7.1", ControlName: "Detection and monitoring procedures"},
		},
	},
	"LLM_JAILBREAK": {
		CWEs: []string{"CWE-693"},
		Controls: []Control{
			{Framework: "OWASP-LLM", ControlID: "LLM08:2025", ControlName: "Jailbreaking / Policy Bypass"},
			{Framework: "NIST-AI", ControlID: "MS-2.5", ControlName: "AI risk and benefit assessments"},
			{Framework: "SOC2", ControlID: "CC7.2", ControlName: "Monitor system components for anomalous behavior"},
		},
	},
	"LLM_EXCESSIVE_AGENCY": {
		CWEs: []string{"CWE-284", "CWE-269"},
		Controls: []Control{
			{Framework: "OWASP-LLM", ControlID: "LLM06:2025", ControlName: "Excessive Agency"},
			{Framework: "NIST-AI", ControlID: "GV-1.6", ControlName: "Organizational teams are committed to AI risk management"},
			{Framework: "ISO27001", ControlID: "A.5.15", ControlName: "Access control"},
			{Framework: "SOC2", ControlID: "CC6.3", ControlName: "Role-based access control"},
		},
	},
	// Network
	"NET_DEFAULT_CREDENTIALS": {
		CWEs: []string{"CWE-521", "CWE-1391"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A07:2021", ControlName: "Identification and Authentication Failures"},
			{Framework: "PCI-DSS", ControlID: "8.3.6", ControlName: "Passwords/passphrases meet complexity requirements"},
			{Framework: "ISO27001", ControlID: "A.8.5", ControlName: "Secure authentication"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical and physical access controls"},
			{Framework: "NIST", ControlID: "IA-5", ControlName: "Authenticator Management"},
		},
	},
	"NET_SUBDOMAIN_TAKEOVER": {
		CWEs: []string{"CWE-350"},
		Controls: []Control{
			{Framework: "OWASP", ControlID: "A05:2021", ControlName: "Security Misconfiguration"},
			{Framework: "ISO27001", ControlID: "A.5.9", ControlName: "Inventory of information and other associated assets"},
			{Framework: "SOC2", ControlID: "CC9.2", ControlName: "Risk management for vendors and business partners"},
			{Framework: "NIST", ControlID: "CM-8", ControlName: "System Component Inventory"},
		},
	},
}

// findingTypeToKey normalises a finding type string to a lookup key.
func findingTypeToKey(findingType string) string {
	upper := strings.ToUpper(findingType)
	// Direct match first
	if _, ok := frameworkControls[upper]; ok {
		return upper
	}
	// Try common aliases
	aliases := map[string]string{
		"SQL_INJECTION": "SQLi", "SQLI": "SQLi",
		"CROSS_SITE_SCRIPTING":             "XSS",
		"SERVER_SIDE_REQUEST_FORGERY":      "SSRF",
		"REMOTE_CODE_EXECUTION":            "RCE",
		"LOCAL_FILE_INCLUSION":             "LFI",
		"INSECURE_DIRECT_OBJECT_REFERENCE": "IDOR",
		"SERVER_SIDE_TEMPLATE_INJECTION":   "SSTI",
		"XML_EXTERNAL_ENTITY":              "XXE",
	}
	if key, ok := aliases[upper]; ok {
		return key
	}
	// Partial prefix match for cloud/net/llm types
	for key := range frameworkControls {
		if strings.HasPrefix(upper, key) || strings.HasPrefix(key, upper) {
			return key
		}
	}
	return ""
}

// MapFinding returns all compliance controls triggered by the given finding type.
func MapFinding(findingType string) FindingMapping {
	key := findingTypeToKey(findingType)
	if key == "" {
		return FindingMapping{FindingType: findingType}
	}
	m := frameworkControls[key]
	m.FindingType = findingType
	return m
}

// SupportedFrameworks returns the list of all compliance framework IDs.
func SupportedFrameworks() []string {
	return []string{"OWASP", "OWASP-LLM", "PCI-DSS", "ISO27001", "SOC2", "NIST", "NIST-AI"}
}

// PostureReport computes a compliance posture for a list of finding types.
type PostureReport struct {
	Framework         string       `json:"framework"`
	TotalControls     int          `json:"total_controls"`
	TriggeredCount    int          `json:"triggered_count"`
	PassRate          float64      `json:"pass_rate"` // 0–1
	TriggeredControls []ControlHit `json:"triggered_controls"`
}

// ControlHit is a control that was triggered by at least one finding.
type ControlHit struct {
	Control      Control  `json:"control"`
	FindingTypes []string `json:"finding_types"`
	Severity     string   `json:"highest_severity"`
}

// GeneratePosture builds per-framework posture reports from a slice of finding types.
func GeneratePosture(findingTypes []string) []PostureReport {
	// Collect all triggered controls per framework
	type controlKey struct{ framework, id string }
	triggered := map[controlKey]*ControlHit{}
	seenTypes := map[controlKey]map[string]bool{}

	for _, ft := range findingTypes {
		mapping := MapFinding(ft)
		for _, ctrl := range mapping.Controls {
			key := controlKey{ctrl.Framework, ctrl.ControlID}
			if triggered[key] == nil {
				triggered[key] = &ControlHit{Control: ctrl}
				seenTypes[key] = map[string]bool{}
			}
			if !seenTypes[key][ft] {
				triggered[key].FindingTypes = append(triggered[key].FindingTypes, ft)
				seenTypes[key][ft] = true
			}
		}
	}

	// Count total unique controls per framework from the full mapping table
	frameworkTotals := map[string]map[string]bool{}
	for _, mapping := range frameworkControls {
		for _, ctrl := range mapping.Controls {
			if frameworkTotals[ctrl.Framework] == nil {
				frameworkTotals[ctrl.Framework] = map[string]bool{}
			}
			frameworkTotals[ctrl.Framework][ctrl.ControlID] = true
		}
	}

	// Build per-framework reports
	frameworkHits := map[string][]*ControlHit{}
	for key, hit := range triggered {
		frameworkHits[key.framework] = append(frameworkHits[key.framework], hit)
	}

	var reports []PostureReport
	for _, fw := range SupportedFrameworks() {
		total := len(frameworkTotals[fw])
		if total == 0 {
			continue
		}
		hits := frameworkHits[fw]
		passRate := 1.0
		if total > 0 {
			passRate = 1.0 - float64(len(hits))/float64(total)
		}
		controls := make([]ControlHit, 0, len(hits))
		for _, h := range hits {
			controls = append(controls, *h)
		}
		reports = append(reports, PostureReport{
			Framework:         fw,
			TotalControls:     total,
			TriggeredCount:    len(hits),
			PassRate:          passRate,
			TriggeredControls: controls,
		})
	}
	return reports
}
