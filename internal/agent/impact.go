package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// BusinessImpact describes the business-level impact of a vulnerability finding.
type BusinessImpact struct {
	Score          float64  // 0-10
	Category       string   // "Data Breach", "Service Disruption", "Privilege Escalation", "Reputational"
	Explanation    string
	AffectedAssets []string
}

// impactEntry is an internal record for base scoring.
type impactEntry struct {
	score    float64
	category string
	base     string // base explanation snippet
}

// impactTable maps normalized vuln type keys to base impact entries.
var impactTable = map[string]impactEntry{
	"sqli":                             {9.5, "Data Breach", "SQL injection provides direct access to the database, enabling full data exfiltration, record modification, and potential OS-level escalation."},
	"sql injection":                    {9.5, "Data Breach", "SQL injection provides direct access to the database, enabling full data exfiltration, record modification, and potential OS-level escalation."},
	"rce":                              {10.0, "Privilege Escalation", "Remote code execution grants full control of the server, enabling lateral movement, data theft, and infrastructure takeover."},
	"remote code execution":            {10.0, "Privilege Escalation", "Remote code execution grants full control of the server, enabling lateral movement, data theft, and infrastructure takeover."},
	"ssti":                             {9.8, "Privilege Escalation", "Server-side template injection commonly leads to remote code execution, allowing complete server compromise."},
	"csti":                             {8.5, "Privilege Escalation", "Client-side template injection allows script execution in the victim's browser, enabling account takeover and data theft."},
	"csti/ssti":                        {9.8, "Privilege Escalation", "Template injection (server or client side) can lead to code execution and full system compromise."},
	"server-side template injection":   {9.8, "Privilege Escalation", "Server-side template injection commonly leads to remote code execution, allowing complete server compromise."},
	"file upload":                      {9.5, "Privilege Escalation", "Unrestricted file upload allows deploying a webshell, leading to remote code execution and full server compromise."},
	"unrestricted file upload":         {9.5, "Privilege Escalation", "Unrestricted file upload allows deploying a webshell, leading to remote code execution and full server compromise."},
	"ssrf (cloud metadata)":            {9.8, "Data Breach", "SSRF to cloud metadata services exposes cloud credentials, enabling full cloud account takeover."},
	"ssrf":                             {6.5, "Data Breach", "Server-side request forgery can expose internal services and sensitive infrastructure data."},
	"ssrf (basic)":                     {6.5, "Data Breach", "Server-side request forgery can expose internal services and sensitive infrastructure data."},
	"xxe":                              {8.0, "Data Breach", "XML external entity injection can read sensitive server files and probe internal network services."},
	"xml external entity":              {8.0, "Data Breach", "XML external entity injection can read sensitive server files and probe internal network services."},
	"lfi":                              {7.5, "Data Breach", "Local file inclusion can expose configuration files, credentials, and sensitive application data."},
	"local file inclusion":             {7.5, "Data Breach", "Local file inclusion can expose configuration files, credentials, and sensitive application data."},
	"jwt":                              {9.0, "Privilege Escalation", "JWT vulnerabilities allow forging authentication tokens, enabling authentication bypass and privilege escalation."},
	"jwt vulnerability":                {9.0, "Privilege Escalation", "JWT vulnerabilities allow forging authentication tokens, enabling authentication bypass and privilege escalation."},
	"idor":                             {8.0, "Data Breach", "Insecure direct object references allow unauthorized access to other users' data and resources."},
	"insecure direct object reference": {8.0, "Data Breach", "Insecure direct object references allow unauthorized access to other users' data and resources."},
	"xss":                              {6.0, "Reputational", "Cross-site scripting enables session hijacking, credential theft, and malicious actions on behalf of victims."},
	"xss (stored)":                     {7.5, "Reputational", "Stored XSS persists and executes for every visitor, enabling mass session hijacking and credential theft."},
	"xss (reflected)":                  {5.5, "Reputational", "Reflected XSS enables targeted phishing attacks that steal session tokens or perform actions as the victim."},
	"stored xss":                       {7.5, "Reputational", "Stored XSS persists and executes for every visitor, enabling mass session hijacking and credential theft."},
	"reflected xss":                    {5.5, "Reputational", "Reflected XSS enables targeted phishing attacks that steal session tokens or perform actions as the victim."},
	"open redirect":                    {5.0, "Reputational", "Open redirects facilitate phishing campaigns that abuse the target's trusted domain reputation."},
	"csrf":                             {6.5, "Data Breach", "Cross-site request forgery tricks authenticated users into performing unintended state-changing actions."},
	"cross-site request forgery":       {6.5, "Data Breach", "Cross-site request forgery tricks authenticated users into performing unintended state-changing actions."},
	"cors":                             {6.0, "Data Breach", "CORS misconfiguration allows malicious sites to make authenticated cross-origin requests and read sensitive responses."},
	"cors misconfiguration":            {6.0, "Data Breach", "CORS misconfiguration allows malicious sites to make authenticated cross-origin requests and read sensitive responses."},
	"deserialization":                  {9.0, "Privilege Escalation", "Insecure deserialization commonly leads to remote code execution or privilege escalation."},
	"insecure deserialization":         {9.0, "Privilege Escalation", "Insecure deserialization commonly leads to remote code execution or privilege escalation."},
	"log4shell":                        {10.0, "Privilege Escalation", "Log4Shell enables unauthenticated remote code execution, granting full server control."},
	"header injection":                 {5.0, "Reputational", "HTTP header injection can enable response splitting and cache poisoning attacks."},
	"host header injection":            {6.5, "Reputational", "Host header injection can enable password reset poisoning and cache poisoning leading to credential theft."},
	"cache poisoning":                  {7.0, "Reputational", "Web cache poisoning can serve malicious content to all users accessing the affected cached responses."},
	"web cache poisoning":              {7.0, "Reputational", "Web cache poisoning can serve malicious content to all users accessing the affected cached responses."},
	"oauth":                            {8.5, "Privilege Escalation", "OAuth misconfiguration can enable account takeover, token theft, and unauthorized access to connected services."},
	"oauth misconfiguration":           {8.5, "Privilege Escalation", "OAuth misconfiguration can enable account takeover, token theft, and unauthorized access to connected services."},
	"prototype pollution":              {7.0, "Privilege Escalation", "Prototype pollution can modify application behavior, potentially leading to authentication bypass or RCE."},
	"business logic":                   {7.5, "Data Breach", "Business logic flaws allow abuse of application workflows, potentially leading to financial fraud or unauthorized data access."},
}

// severityMultiplier adjusts the base score based on confirmed severity.
var severityMultiplier = map[string]float64{
	"critical": 1.0,
	"high":     0.9,
	"medium":   0.7,
	"low":      0.5,
	"info":     0.3,
}

// BusinessImpactScore computes the business impact for a given finding.
func BusinessImpactScore(f *Finding) BusinessImpact {
	key := strings.ToLower(strings.TrimSpace(f.Type))

	entry, ok := impactTable[key]
	if !ok {
		// Fuzzy match.
		for k, e := range impactTable {
			if strings.Contains(key, k) || strings.Contains(k, key) {
				entry = e
				ok = true
				break
			}
		}
	}

	if !ok {
		entry = impactEntry{
			score:    5.0,
			category: "Data Breach",
			base:     "This vulnerability could expose sensitive data or allow unauthorized actions.",
		}
	}

	// Apply severity multiplier.
	mult, hasMult := severityMultiplier[strings.ToLower(strings.TrimSpace(f.Severity))]
	if !hasMult {
		mult = 0.7
	}

	score := entry.score * mult
	if score > 10.0 {
		score = 10.0
	}

	// Build context-enriched explanation.
	explanation := entry.base
	if strings.Contains(key, "sqli") || strings.Contains(key, "sql injection") {
		if strings.Contains(strings.ToLower(f.Payload), "password") ||
			strings.Contains(strings.ToLower(f.Payload), "credential") ||
			strings.Contains(strings.ToLower(f.Payload), "admin") {
			explanation += " Evidence suggests access to credential or admin data, elevating impact to critical."
			score = min10(score + 0.5)
		}
	}
	if strings.Contains(key, "ssrf") && strings.Contains(strings.ToLower(f.Evidence["body"].(string)), "iam/security") {
		explanation += " Cloud IAM credentials were exposed, escalating to full cloud account takeover."
		score = min10(score + 1.0)
	}

	// Determine affected assets from the URL.
	assets := extractAffectedAssets(f)

	return BusinessImpact{
		Score:          roundTo1dp(score),
		Category:       entry.category,
		Explanation:    explanation,
		AffectedAssets: assets,
	}
}

// extractAffectedAssets derives a list of affected assets from the finding.
func extractAffectedAssets(f *Finding) []string {
	var assets []string

	if f.URL != "" {
		u, err := url.Parse(f.URL)
		if err == nil {
			assets = append(assets, fmt.Sprintf("Host: %s", u.Hostname()))
			if u.Path != "" && u.Path != "/" {
				assets = append(assets, fmt.Sprintf("Endpoint: %s", u.Path))
			}
		}
	}

	if f.Parameter != "" {
		assets = append(assets, fmt.Sprintf("Parameter: %s", f.Parameter))
	}

	if f.Agent != "" {
		assets = append(assets, fmt.Sprintf("Detected by: %s", f.Agent))
	}

	if len(assets) == 0 {
		assets = []string{"Unknown asset"}
	}
	return assets
}

func min10(v float64) float64 {
	if v > 10.0 {
		return 10.0
	}
	return v
}

func roundTo1dp(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
