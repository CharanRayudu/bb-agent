package agent

import (
	"fmt"
	"strings"
)

// DetectedChain describes a multi-step attack path inferred from confirmed findings.
type DetectedChain struct {
	Name        string
	Steps       []string   // e.g. ["LFI → /var/log/apache2/access.log", "Log Poisoning → RCE"]
	Findings    []*Finding // the confirmed findings that enable this chain
	ChainType   string     // e.g. "LFI→RCE", "SSRF→CloudCreds", "XSS→CSRF"
	Severity    string     // combined severity
	Description string
}

// ChainExecutor detects possible exploit chains from confirmed findings.
type ChainExecutor struct{}

// NewChainExecutor creates a new ChainExecutor.
func NewChainExecutor() *ChainExecutor { return &ChainExecutor{} }

// hasType returns the first finding whose Type field matches (case-insensitive) any
// of the provided substrings, or nil if none match.
func hasType(findings []*Finding, substrings ...string) *Finding {
	for _, f := range findings {
		lower := strings.ToLower(f.Type)
		for _, s := range substrings {
			if strings.Contains(lower, strings.ToLower(s)) {
				return f
			}
		}
	}
	return nil
}

// evidenceContains checks whether any evidence value in the finding contains one of
// the provided keywords (case-insensitive).
func evidenceContains(f *Finding, keywords ...string) bool {
	for _, v := range f.Evidence {
		s := strings.ToLower(fmt.Sprintf("%v", v))
		for _, kw := range keywords {
			if strings.Contains(s, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

// combinedSeverity returns the most severe label from a set of findings.
func combinedSeverity(findings ...*Finding) string {
	rank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}
	best := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		if r, ok := rank[strings.ToLower(f.Severity)]; ok && r > best {
			best = r
		}
	}
	for sev, r := range rank {
		if r == best {
			// Capitalise first letter.
			return strings.ToUpper(sev[:1]) + sev[1:]
		}
	}
	return "Medium"
}

// DetectChains analyzes confirmed findings and returns exploit chains.
func (ce *ChainExecutor) DetectChains(findings []*Finding) []DetectedChain {
	var chains []DetectedChain

	// 1. LFI → RCE via log poisoning or PHP wrapper
	if lfi := hasType(findings, "lfi", "local file inclusion"); lfi != nil {
		if evidenceContains(lfi, "log_poisoning", "log poisoning", "php_wrapper", "php://") {
			chains = append(chains, DetectedChain{
				Name: "LFI → Remote Code Execution",
				Steps: []string{
					"LFI → Read /var/log/apache2/access.log (or php://filter wrapper)",
					"Log Poisoning → Inject PHP code via User-Agent header",
					"RCE → Request poisoned log file to execute injected code",
					"Shell → Establish reverse shell or webshell for persistent access",
				},
				Findings:  []*Finding{lfi},
				ChainType: "LFI→RCE",
				Severity:  "Critical",
				Description: "The confirmed LFI vulnerability allows reading server log files. By " +
					"injecting malicious PHP code through HTTP headers (log poisoning) or leveraging " +
					"PHP stream wrappers, an attacker can escalate file read to full remote code execution.",
			})
		}
	}

	// 2. SSRF → Cloud Credential Theft
	if ssrf := hasType(findings, "ssrf"); ssrf != nil {
		isCloud := evidenceContains(ssrf, "cloud_metadata", "cloud metadata", "169.254.169.254",
			"metadata.google", "metadata.internal", "iam", "aws", "gcp", "azure")
		ssrfTypeMeta := false
		if v, ok := ssrf.Evidence["ssrf_type"]; ok {
			ssrfTypeMeta = strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), "cloud_metadata")
		}
		if isCloud || ssrfTypeMeta {
			chains = append(chains, DetectedChain{
				Name: "SSRF → Cloud Credential Theft",
				Steps: []string{
					"SSRF → Reach cloud metadata endpoint (169.254.169.254 / fd00:ec2::254)",
					"IAM Role Enumeration → Retrieve attached IAM role name",
					"Credential Extraction → Fetch temporary AWS/GCP/Azure credentials",
					"Pivot → Use credentials to access S3 buckets, secrets, or internal APIs",
				},
				Findings:  []*Finding{ssrf},
				ChainType: "SSRF→CloudCreds",
				Severity:  "Critical",
				Description: "The SSRF vulnerability reaches the cloud instance metadata service. " +
					"An attacker can extract short-lived IAM credentials and use them to pivot into " +
					"the cloud environment, accessing object storage, secrets, and internal services.",
			})
		}
	}

	// 3. SQLi → Credential Dump
	if sqli := hasType(findings, "sqli", "sql injection"); sqli != nil {
		if evidenceContains(sqli, "db_error", "error", "confirmed") || sqli.Confidence >= 0.7 {
			chains = append(chains, DetectedChain{
				Name: "SQL Injection → Credential Dump",
				Steps: []string{
					"SQLi → Enumerate database schema (UNION SELECT / error-based)",
					"DB Dump → Extract users/credentials table",
					"Credential Extraction → Recover plaintext or hashed passwords",
					"Password Cracking → Offline crack hashes (hashcat/john)",
					"Account Takeover → Authenticate to application or other services with recovered creds",
				},
				Findings:  []*Finding{sqli},
				ChainType: "SQLi→CredDump",
				Severity:  "Critical",
				Description: "The confirmed SQL injection allows full database read access. " +
					"An attacker can dump the credentials table, crack password hashes offline, " +
					"and leverage the credentials for lateral movement.",
			})
		}
	}

	// 4. XSS → Session Hijacking
	if xss := hasType(findings, "xss"); xss != nil {
		if xss.Confidence > 0.7 {
			chains = append(chains, DetectedChain{
				Name: "XSS → Session Hijacking → Account Takeover",
				Steps: []string{
					"XSS → Inject script that exfiltrates document.cookie to attacker server",
					"Cookie Theft → Receive session token via out-of-band HTTP request",
					"Session Hijacking → Replay stolen session cookie",
					"Account Takeover → Operate as victim user; escalate if admin",
				},
				Findings:  []*Finding{xss},
				ChainType: "XSS→SessionHijack",
				Severity:  combinedSeverity(xss),
				Description: "The high-confidence XSS vulnerability enables an attacker to steal " +
					"authenticated users' session cookies, leading to full account takeover. " +
					"Stored XSS variants allow persistent, scalable attacks.",
			})
		}
	}

	// 5. IDOR → PII Exposure
	if idor := hasType(findings, "idor", "insecure direct object"); idor != nil {
		chains = append(chains, DetectedChain{
			Name: "IDOR → PII Exposure → Regulatory Impact",
			Steps: []string{
				"IDOR → Enumerate sequential resource IDs (e.g., /api/users/1, /api/users/2, ...)",
				"PII Leak → Access personal data (names, emails, addresses, payment info) of all users",
				"Mass Extraction → Automate full database scrape via ID iteration",
				"Regulatory Impact → GDPR / CCPA / PCI-DSS breach notification obligations triggered",
			},
			Findings:  []*Finding{idor},
			ChainType: "IDOR→PIILeak",
			Severity:  combinedSeverity(idor),
			Description: "The IDOR vulnerability allows unauthenticated or low-privilege attackers " +
				"to iterate over resource IDs and access other users' private data, constituting a " +
				"reportable personal data breach under GDPR, CCPA, and similar regulations.",
		})
	}

	// 6. JWT → Admin Escalation
	if jwt := hasType(findings, "jwt"); jwt != nil {
		chains = append(chains, DetectedChain{
			Name: "JWT Bypass → Admin Privilege Escalation → Full Compromise",
			Steps: []string{
				"JWT Bypass → Forge or manipulate token (none-alg, HS256/RS256 confusion, weak secret)",
				"Privilege Escalation → Craft token with admin/superuser role claim",
				"Admin Access → Access admin panel, management APIs, or sensitive operations",
				"Full Compromise → Exfiltrate data, create backdoor accounts, modify application logic",
			},
			Findings:  []*Finding{jwt},
			ChainType: "JWT→AdminEscalation",
			Severity:  "Critical",
			Description: "The JWT vulnerability allows token forgery or algorithm confusion attacks. " +
				"An attacker can craft a token with elevated privileges, gaining admin access and " +
				"the ability to fully compromise the application and its data.",
		})
	}

	// 7. File Upload → RCE via Webshell
	if upload := hasType(findings, "file upload", "unrestricted file upload"); upload != nil {
		chains = append(chains, DetectedChain{
			Name: "Unrestricted File Upload → Webshell → RCE",
			Steps: []string{
				"File Upload → Upload PHP/JSP/ASPX webshell bypassing extension/MIME filters",
				"Webshell Access → Navigate to uploaded file URL to confirm code execution",
				"RCE → Execute OS commands via webshell (id, whoami, cat /etc/passwd)",
				"Persistence → Drop SSH key, cron job, or reverse shell for persistent access",
				"Lateral Movement → Use server foothold to reach internal network",
			},
			Findings:  []*Finding{upload},
			ChainType: "FileUpload→RCE",
			Severity:  "Critical",
			Description: "The unrestricted file upload vulnerability allows an attacker to upload " +
				"a server-side script (webshell). Once the webshell is accessible via the web server, " +
				"the attacker achieves full remote code execution on the host operating system.",
		})
	}

	return chains
}

// FormatChainReport generates a markdown section describing discovered chains.
func (ce *ChainExecutor) FormatChainReport(chains []DetectedChain) string {
	if len(chains) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Exploit Chains\n\n")
	sb.WriteString(fmt.Sprintf(
		"> **%d exploit chain(s) detected.** The following multi-step attack paths were identified "+
			"from the confirmed findings. Each chain represents a realistic escalation scenario.\n\n",
		len(chains),
	))

	for i, chain := range chains {
		sb.WriteString(fmt.Sprintf("### Chain %d: %s\n\n", i+1, chain.Name))
		sb.WriteString(fmt.Sprintf("**Type:** `%s`  \n", chain.ChainType))
		sb.WriteString(fmt.Sprintf("**Combined Severity:** %s  \n", chain.Severity))
		sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", chain.Description))

		sb.WriteString("**Attack Steps:**\n\n")
		for j, step := range chain.Steps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", j+1, step))
		}
		sb.WriteString("\n")

		if len(chain.Findings) > 0 {
			sb.WriteString("**Source Findings:**\n\n")
			for _, f := range chain.Findings {
				sb.WriteString(fmt.Sprintf("- **%s** at `%s` (Severity: %s, Confidence: %.0f%%)\n",
					f.Type, f.URL, f.Severity, f.Confidence*100))
			}
			sb.WriteString("\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}
