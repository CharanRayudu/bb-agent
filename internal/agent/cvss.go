package agent

import "strings"

// CVSSScore holds a CVSS 3.1 assessment for a finding.
type CVSSScore struct {
	Score       float64 // 0.0 - 10.0
	Vector      string  // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
	Severity    string  // "Critical", "High", "Medium", "Low", "None"
	Exploitable string  // "Trivial", "Easy", "Moderate", "Hard"
}

// Remediation holds fix guidance for a vulnerability type.
type Remediation struct {
	Summary    string
	Steps      []string
	References []string
	Priority   string // "Immediate", "High", "Medium", "Low"
}

// cvssEntry is an internal lookup record.
type cvssEntry struct {
	score       float64
	vector      string
	severity    string
	exploitable string
}

// cvssTable maps normalized vuln type keys to CVSS 3.1 entries.
var cvssTable = map[string]cvssEntry{
	"xss":                {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"xss (stored)":       {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"xss (reflected)":    {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"stored xss":         {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"reflected xss":      {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"sqli":               {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"sql injection":      {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"ssrf (cloud metadata)": {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "Critical", "Trivial"},
	"ssrf":               {6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium", "Easy"},
	"ssrf (basic)":       {6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium", "Easy"},
	"lfi":                {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High", "Easy"},
	"local file inclusion": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High", "Easy"},
	"rce":                {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"remote code execution": {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"xxe":                {8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "High", "Easy"},
	"xml external entity": {8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "High", "Easy"},
	"idor":               {8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "High", "Easy"},
	"insecure direct object reference": {8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "High", "Easy"},
	"open redirect":      {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium", "Easy"},
	"csti":               {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical", "Trivial"},
	"ssti":               {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical", "Trivial"},
	"csti/ssti":          {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical", "Trivial"},
	"server-side template injection": {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical", "Trivial"},
	"header injection":   {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium", "Moderate"},
	"prototype pollution": {7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "High", "Moderate"},
	"jwt":                {9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Critical", "Easy"},
	"jwt vulnerability":  {9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Critical", "Easy"},
	"file upload":        {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"unrestricted file upload": {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Trivial"},
	"business logic":     {8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "High", "Moderate"},
}

// defaultCVSS is returned for unrecognized vulnerability types.
var defaultCVSS = cvssEntry{
	score:       6.5,
	vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
	severity:    "Medium",
	exploitable: "Easy",
}

// ScoreFinding calculates a CVSS 3.1 base score for a finding.
func ScoreFinding(f *Finding) CVSSScore {
	key := strings.ToLower(strings.TrimSpace(f.Type))
	entry, ok := cvssTable[key]
	if !ok {
		entry = defaultCVSS
	}
	return CVSSScore{
		Score:       entry.score,
		Vector:      entry.vector,
		Severity:    entry.severity,
		Exploitable: entry.exploitable,
	}
}

// remediationTable maps normalized vuln type keys to Remediation guidance.
var remediationTable = map[string]Remediation{
	"xss": {
		Summary:  "Prevent Cross-Site Scripting by encoding output and enforcing a strict Content Security Policy.",
		Priority: "High",
		Steps: []string{
			"Encode all user-supplied data before rendering in HTML (use HTML entity encoding).",
			"Implement a strict Content-Security-Policy (CSP) header that disallows inline scripts.",
			"Validate and allowlist input server-side; reject or strip unexpected characters.",
			"Use template engines that auto-escape by default (e.g., Go's html/template, Jinja2 with autoescaping).",
			"Apply the HTTPOnly and Secure flags to session cookies to limit impact of any bypass.",
		},
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
	},
	"sqli": {
		Summary:  "Prevent SQL Injection by using parameterized queries and limiting database permissions.",
		Priority: "Immediate",
		Steps: []string{
			"Replace all dynamic SQL string concatenation with parameterized queries or prepared statements.",
			"Use an ORM (e.g., GORM, Hibernate, SQLAlchemy) with built-in query parameterization.",
			"Apply least-privilege database accounts — the app DB user should not have DROP/ALTER rights.",
			"Implement input validation with an allowlist of expected characters and lengths.",
			"Deploy a Web Application Firewall (WAF) rule set targeting SQL injection patterns as a defense-in-depth layer.",
			"Enable database audit logging to detect and alert on suspicious query patterns.",
		},
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
	},
	"ssrf": {
		Summary:  "Prevent Server-Side Request Forgery by restricting outbound connections to an allowlist.",
		Priority: "Immediate",
		Steps: []string{
			"Implement a strict allowlist of permitted destination URLs or IP ranges; deny all others.",
			"Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1, ::1).",
			"Block access to cloud metadata endpoints (169.254.169.254, fd00:ec2::254).",
			"Disable unused URL schemes (file://, gopher://, ftp://) in HTTP client configuration.",
			"Perform DNS resolution server-side and validate the resolved IP against the blocklist (prevent DNS rebinding).",
			"Use network segmentation so the application server cannot reach internal services.",
		},
		References: []string{
			"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		},
	},
	"lfi": {
		Summary:  "Prevent Local File Inclusion by restricting the file system paths accessible to user input.",
		Priority: "Immediate",
		Steps: []string{
			"Never pass raw user input directly to file-read functions; use a strict allowlist of permitted filenames or IDs.",
			"Resolve the canonical path of any requested file and verify it is inside the expected directory (chroot or prefix check).",
			"Disable dangerous PHP wrappers (php://input, php://filter, expect://) in php.ini if applicable.",
			"Run the web application process with minimal OS file-system permissions (principle of least privilege).",
			"Apply input sanitization to strip traversal sequences (../, ..\\, %2e%2e) before any path construction.",
		},
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
		},
	},
	"rce": {
		Summary:  "Prevent Remote Code Execution by avoiding OS command invocation with user input.",
		Priority: "Immediate",
		Steps: []string{
			"Eliminate calls to exec(), system(), popen(), eval(), or shell_exec() that incorporate user-supplied data.",
			"If OS commands are unavoidable, use argument arrays (not shell interpolation) and apply strict input allowlisting.",
			"Run the application inside a sandbox (container, seccomp profile, AppArmor/SELinux) to limit blast radius.",
			"Integrate Static Application Security Testing (SAST) into CI/CD to catch dangerous function usage early.",
			"Apply network egress filtering so a compromised server cannot beacon out or download additional payloads.",
		},
		References: []string{
			"https://owasp.org/www-community/attacks/Code_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
		},
	},
	"idor": {
		Summary:  "Prevent Insecure Direct Object Reference by enforcing object-level authorization on every request.",
		Priority: "Immediate",
		Steps: []string{
			"Implement object-level authorization checks: verify the authenticated user owns or is permitted to access the requested resource ID on every API endpoint.",
			"Replace sequential integer IDs exposed in URLs/parameters with UUIDs or cryptographically random identifiers.",
			"Centralize authorization logic in a reusable middleware or service layer rather than repeating checks per endpoint.",
			"Log and alert on repeated access attempts to IDs the user does not own.",
		},
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
		},
	},
	"jwt": {
		Summary:  "Harden JSON Web Token implementation to prevent algorithm confusion and forgery attacks.",
		Priority: "Immediate",
		Steps: []string{
			"Explicitly specify and enforce the expected signing algorithm (RS256 or ES256); never accept 'none' or HS256 when RS256 is expected.",
			"Validate the 'alg' header server-side and reject tokens with unexpected algorithms.",
			"Set a short token expiry (exp claim) and implement token refresh with revocation support.",
			"Rotate signing secrets/keys regularly and store them securely (e.g., AWS Secrets Manager, HashiCorp Vault).",
			"Validate all standard claims: iss, aud, exp, nbf on every request.",
		},
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
			"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
		},
	},
	"file upload": {
		Summary:  "Secure file upload functionality to prevent webshell upload and RCE.",
		Priority: "Immediate",
		Steps: []string{
			"Allowlist accepted file extensions (e.g., .jpg, .png, .pdf) and reject everything else.",
			"Validate the file's magic bytes/MIME type server-side, not just the Content-Type header supplied by the client.",
			"Store uploaded files outside the web root in a location the web server cannot execute.",
			"Rename uploaded files to a random UUID, stripping the original filename entirely.",
			"Scan uploaded files with an antivirus/anti-malware engine before making them accessible.",
			"Set the upload directory with no-execute permissions at the OS level.",
		},
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		},
	},
	"xxe": {
		Summary:  "Prevent XML External Entity injection by disabling external entity processing.",
		Priority: "Immediate",
		Steps: []string{
			"Disable DOCTYPE declarations and external entity resolution in your XML parser configuration.",
			"Use a safe XML parsing library or mode (e.g., Go's encoding/xml with default settings; set LIBXML_NONET in libxml2).",
			"If XML input is not required, prefer a simpler data format such as JSON.",
			"Validate and sanitize XML input before parsing; reject documents with DOCTYPE declarations.",
		},
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
			"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
		},
	},
	"open redirect": {
		Summary:  "Prevent Open Redirect by validating redirect destinations against an allowlist.",
		Priority: "Medium",
		Steps: []string{
			"Allowlist permitted redirect destinations; reject or encode any URL that does not match.",
			"Avoid reflecting user-supplied URLs directly; use indirection tokens that map to fixed destinations server-side.",
			"Display a redirect warning page informing users they are leaving the site.",
		},
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
		},
	},
	"csti": {
		Summary:  "Prevent template injection by never evaluating user input as template code.",
		Priority: "Immediate",
		Steps: []string{
			"Never pass user-controlled strings to template rendering functions as template source.",
			"Use sandboxed template engines with expression evaluation disabled.",
			"Apply strict output encoding when embedding user data inside templates.",
			"Audit all template render calls in the codebase for untrusted input.",
		},
		References: []string{
			"https://portswigger.net/research/server-side-template-injection",
		},
	},
	"ssti": {
		Summary:  "Prevent server-side template injection by never evaluating user input as template code.",
		Priority: "Immediate",
		Steps: []string{
			"Never pass user-controlled strings to template rendering functions as template source.",
			"Use sandboxed template engines with expression evaluation disabled.",
			"Apply strict output encoding when embedding user data inside templates.",
			"Audit all template render calls in the codebase for untrusted input.",
		},
		References: []string{
			"https://portswigger.net/research/server-side-template-injection",
		},
	},
	"header injection": {
		Summary:  "Prevent HTTP header injection by stripping newline characters from header values.",
		Priority: "Medium",
		Steps: []string{
			"Strip or reject CR (\\r) and LF (\\n) characters from any user input included in HTTP response headers.",
			"Use framework-provided header-setting APIs rather than raw string concatenation.",
			"Validate and encode redirect URLs before including them in Location headers.",
		},
		References: []string{
			"https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
		},
	},
	"prototype pollution": {
		Summary:  "Prevent prototype pollution by sanitizing object keys and avoiding unsafe merge patterns.",
		Priority: "High",
		Steps: []string{
			"Reject or sanitize keys such as __proto__, constructor, and prototype from any user-supplied JSON or object.",
			"Use Object.create(null) for dictionaries that should not inherit from Object.prototype.",
			"Replace unsafe deep-merge libraries with hardened alternatives (e.g., lodash >= 4.17.21 with recursive merge fixes).",
			"Enable frozen objects or use Map instead of plain objects for untrusted key-value storage.",
		},
		References: []string{
			"https://portswigger.net/web-security/prototype-pollution",
		},
	},
	"business logic": {
		Summary:  "Remediate business logic flaws by enforcing server-side state and authorization checks.",
		Priority: "High",
		Steps: []string{
			"Enforce all business rules server-side; never rely solely on client-side controls.",
			"Implement rate limiting and transaction limits to prevent abuse of workflows.",
			"Add integrity checks to multi-step workflows to ensure steps are completed in order and by the same authenticated user.",
			"Conduct dedicated manual review of checkout, transfer, and other high-value flows.",
		},
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
		},
	},
}

// defaultRemediation is returned for unrecognized vulnerability types.
var defaultRemediation = Remediation{
	Summary:  "Apply defence-in-depth: validate all inputs, enforce least privilege, and audit regularly.",
	Priority: "High",
	Steps: []string{
		"Validate and sanitize all user-supplied input server-side.",
		"Apply the principle of least privilege to all system components.",
		"Enable detailed security logging and alerting.",
		"Conduct regular security code reviews and penetration tests.",
	},
	References: []string{
		"https://owasp.org/www-project-top-ten/",
	},
}

// RemediationFor returns remediation guidance for a vulnerability type.
func RemediationFor(vulnType string) Remediation {
	key := strings.ToLower(strings.TrimSpace(vulnType))

	// Direct lookup first.
	if r, ok := remediationTable[key]; ok {
		return r
	}

	// Fuzzy match: check if the key contains a known type substring.
	for k, r := range remediationTable {
		if strings.Contains(key, k) || strings.Contains(k, key) {
			return r
		}
	}

	return defaultRemediation
}
