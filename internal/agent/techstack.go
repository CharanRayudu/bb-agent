package agent

import (
	"regexp"
	"strings"
)

// TechComponent represents a single detected technology component.
type TechComponent struct {
	Name       string  // e.g. "PHP", "WordPress", "nginx"
	Version    string  // detected version string, may be empty
	Category   string  // "framework", "language", "server", "database", "cdn", "waf"
	Confidence float64 // 0.0 – 1.0
	Source     string  // "header", "cookie", "response_body", "error_message"
}

// TechStackAnalysis holds the full set of detected components and recommended specialists.
// Named TechStackAnalysis to avoid conflict with the existing TechStack struct in context.go.
type TechStackAnalysis struct {
	Components    []TechComponent
	AttackVectors []string // recommended specialist IDs based on detected tech
}

// headerRule maps a header name + value substring to a TechComponent.
type headerRule struct {
	header     string
	valueSub   string // case-insensitive substring match on the value; empty = presence only
	component  TechComponent
}

// cookieRule maps a cookie name substring to a TechComponent.
type cookieRule struct {
	nameSub   string // case-insensitive
	component TechComponent
}

// bodyRule matches a regex pattern in the response body.
type bodyRule struct {
	pattern    *regexp.Regexp
	component  TechComponent
}

var headerRules = []headerRule{
	// --- Server ---
	{"Server", "nginx", TechComponent{Name: "nginx", Category: "server", Confidence: 0.95, Source: "header"}},
	{"Server", "apache", TechComponent{Name: "Apache", Category: "server", Confidence: 0.95, Source: "header"}},
	{"Server", "iis", TechComponent{Name: "IIS", Category: "server", Confidence: 0.95, Source: "header"}},
	{"Server", "gunicorn", TechComponent{Name: "gunicorn", Category: "server", Confidence: 0.92, Source: "header"}},
	{"Server", "lighttpd", TechComponent{Name: "lighttpd", Category: "server", Confidence: 0.92, Source: "header"}},
	{"Server", "caddy", TechComponent{Name: "Caddy", Category: "server", Confidence: 0.90, Source: "header"}},
	{"Server", "openresty", TechComponent{Name: "OpenResty", Category: "server", Confidence: 0.90, Source: "header"}},
	{"Server", "AkamaiGHost", TechComponent{Name: "Akamai", Category: "cdn", Confidence: 0.92, Source: "header"}},
	// --- X-Powered-By ---
	{"X-Powered-By", "php", TechComponent{Name: "PHP", Category: "language", Confidence: 0.95, Source: "header"}},
	{"X-Powered-By", "asp.net", TechComponent{Name: "ASP.NET", Category: "framework", Confidence: 0.95, Source: "header"}},
	{"X-Powered-By", "express", TechComponent{Name: "Express", Category: "framework", Confidence: 0.92, Source: "header"}},
	{"X-Powered-By", "next.js", TechComponent{Name: "Next.js", Category: "framework", Confidence: 0.92, Source: "header"}},
	{"X-Powered-By", "django", TechComponent{Name: "Django", Category: "framework", Confidence: 0.92, Source: "header"}},
	{"X-Powered-By", "rails", TechComponent{Name: "Ruby on Rails", Category: "framework", Confidence: 0.92, Source: "header"}},
	// --- CDN ---
	{"X-Cache", "cloudfront", TechComponent{Name: "CloudFront", Category: "cdn", Confidence: 0.88, Source: "header"}},
	{"Cf-Ray", "", TechComponent{Name: "Cloudflare", Category: "cdn", Confidence: 0.97, Source: "header"}},
	{"X-Sucuri-Id", "", TechComponent{Name: "Sucuri", Category: "waf", Confidence: 0.95, Source: "header"}},
	{"X-Iinfo", "", TechComponent{Name: "Incapsula", Category: "waf", Confidence: 0.95, Source: "header"}},
	// --- WAF ---
	{"X-Waf", "", TechComponent{Name: "WAF", Category: "waf", Confidence: 0.80, Source: "header"}},
}

var cookieRules = []cookieRule{
	{"phpsessid", TechComponent{Name: "PHP", Category: "language", Confidence: 0.90, Source: "cookie"}},
	{"jsessionid", TechComponent{Name: "Java", Category: "language", Confidence: 0.90, Source: "cookie"}},
	{"asp.net_sessionid", TechComponent{Name: "ASP.NET", Category: "framework", Confidence: 0.92, Source: "cookie"}},
	{"laravel_session", TechComponent{Name: "Laravel", Category: "framework", Confidence: 0.92, Source: "cookie"}},
	{"ci_session", TechComponent{Name: "CodeIgniter", Category: "framework", Confidence: 0.88, Source: "cookie"}},
	{"django", TechComponent{Name: "Django", Category: "framework", Confidence: 0.85, Source: "cookie"}},
	{"rack.session", TechComponent{Name: "Ruby/Rack", Category: "framework", Confidence: 0.85, Source: "cookie"}},
	{"connect.sid", TechComponent{Name: "Express/Node.js", Category: "framework", Confidence: 0.88, Source: "cookie"}},
	{"wordpress_", TechComponent{Name: "WordPress", Category: "framework", Confidence: 0.95, Source: "cookie"}},
	{"drupal", TechComponent{Name: "Drupal", Category: "framework", Confidence: 0.90, Source: "cookie"}},
	{"joomla", TechComponent{Name: "Joomla", Category: "framework", Confidence: 0.90, Source: "cookie"}},
	{"_ga", TechComponent{Name: "Google Analytics", Category: "cdn", Confidence: 0.60, Source: "cookie"}},
	{"__cfduid", TechComponent{Name: "Cloudflare", Category: "cdn", Confidence: 0.88, Source: "cookie"}},
	{"incap_ses", TechComponent{Name: "Incapsula", Category: "waf", Confidence: 0.92, Source: "cookie"}},
}

var bodyRules = []bodyRule{
	{
		regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`),
		TechComponent{Name: "WordPress", Category: "framework", Confidence: 0.90, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)drupal`),
		TechComponent{Name: "Drupal", Category: "framework", Confidence: 0.88, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)joomla`),
		TechComponent{Name: "Joomla", Category: "framework", Confidence: 0.88, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)__VIEWSTATE|__EVENTVALIDATION`),
		TechComponent{Name: "ASP.NET WebForms", Category: "framework", Confidence: 0.95, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)react\.production\.min\.js|data-reactroot|__NEXT_DATA__`),
		TechComponent{Name: "React", Category: "framework", Confidence: 0.88, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)__NEXT_DATA__`),
		TechComponent{Name: "Next.js", Category: "framework", Confidence: 0.90, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)ng-version|angular\.min\.js`),
		TechComponent{Name: "Angular", Category: "framework", Confidence: 0.88, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)vue\.min\.js|vue\.js`),
		TechComponent{Name: "Vue.js", Category: "framework", Confidence: 0.85, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)jquery\.min\.js|jquery-`),
		TechComponent{Name: "jQuery", Category: "framework", Confidence: 0.75, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)laravel`),
		TechComponent{Name: "Laravel", Category: "framework", Confidence: 0.80, Source: "response_body"},
	},
	{
		regexp.MustCompile(`(?i)symfony`),
		TechComponent{Name: "Symfony", Category: "framework", Confidence: 0.80, Source: "response_body"},
	},
	// Error message patterns
	{
		regexp.MustCompile(`(?i)fatal error.*php|parse error.*php|warning.*php.*on line`),
		TechComponent{Name: "PHP", Category: "language", Confidence: 0.98, Source: "error_message"},
	},
	{
		regexp.MustCompile(`(?i)java\.lang\.|at org\.|at com\.|NullPointerException`),
		TechComponent{Name: "Java", Category: "language", Confidence: 0.98, Source: "error_message"},
	},
	{
		regexp.MustCompile(`(?i)Traceback \(most recent call last\)|File ".*\.py"`),
		TechComponent{Name: "Python", Category: "language", Confidence: 0.98, Source: "error_message"},
	},
	{
		regexp.MustCompile(`(?i)ActionController|ActionView|ActiveRecord`),
		TechComponent{Name: "Ruby on Rails", Category: "framework", Confidence: 0.95, Source: "error_message"},
	},
	{
		regexp.MustCompile(`(?i)System\.Web\.|System\.Data\.|ASP\.NET`),
		TechComponent{Name: "ASP.NET", Category: "framework", Confidence: 0.95, Source: "error_message"},
	},
}

// AnalyzeTechStack detects technology from HTTP response headers and body.
func AnalyzeTechStack(headers map[string][]string, body string) TechStackAnalysis {
	seen := make(map[string]bool) // deduplicate by Name
	var components []TechComponent

	addComponent := func(c TechComponent) {
		if seen[c.Name] {
			return
		}
		seen[c.Name] = true
		components = append(components, c)
	}

	// --- Check headers ---
	for _, rule := range headerRules {
		vals, ok := headers[rule.header]
		if !ok {
			// Try canonical casing
			vals, ok = headers[canonicalKey(rule.header)]
			if !ok {
				continue
			}
		}
		combined := strings.ToLower(strings.Join(vals, " "))
		if rule.valueSub == "" || strings.Contains(combined, strings.ToLower(rule.valueSub)) {
			// Extract version if header value matches "PHP/X.Y.Z"
			c := rule.component
			if c.Version == "" {
				c.Version = extractVersion(combined)
			}
			addComponent(c)
		}
	}

	// --- Check Set-Cookie header for session tokens ---
	for key, vals := range headers {
		if !strings.EqualFold(key, "set-cookie") {
			continue
		}
		for _, v := range vals {
			vLower := strings.ToLower(v)
			for _, cr := range cookieRules {
				if strings.Contains(vLower, cr.nameSub) {
					addComponent(cr.component)
				}
			}
		}
	}

	// --- Check response body ---
	for _, rule := range bodyRules {
		if rule.pattern.MatchString(body) {
			addComponent(rule.component)
		}
	}

	stack := TechStackAnalysis{
		Components:    components,
		AttackVectors: RecommendSpecialists(TechStackAnalysis{Components: components}),
	}
	return stack
}

// RecommendSpecialists returns specialist IDs most relevant for the detected tech.
func RecommendSpecialists(stack TechStackAnalysis) []string {
	recommendations := make(map[string]bool)

	for _, c := range stack.Components {
		nameLower := strings.ToLower(c.Name)
		catLower := strings.ToLower(c.Category)

		switch {
		case strings.Contains(nameLower, "php") || strings.Contains(nameLower, "laravel") ||
			strings.Contains(nameLower, "symfony") || strings.Contains(nameLower, "codeigniter"):
			recommendations["sqli"] = true
			recommendations["lfi"] = true
			recommendations["rce"] = true
			recommendations["xss"] = true

		case strings.Contains(nameLower, "asp.net") || strings.Contains(nameLower, "iis"):
			recommendations["sqli"] = true
			recommendations["xss"] = true
			recommendations["xxe"] = true
			recommendations["deserialization"] = true

		case strings.Contains(nameLower, "java") || strings.Contains(nameLower, "spring") ||
			strings.Contains(nameLower, "struts"):
			recommendations["xxe"] = true
			recommendations["deserialization"] = true
			recommendations["sqli"] = true
			recommendations["rce"] = true

		case strings.Contains(nameLower, "python") || strings.Contains(nameLower, "django") ||
			strings.Contains(nameLower, "flask"):
			recommendations["ssti"] = true
			recommendations["sqli"] = true
			recommendations["ssrf"] = true

		case strings.Contains(nameLower, "ruby") || strings.Contains(nameLower, "rails"):
			recommendations["ssti"] = true
			recommendations["sqli"] = true
			recommendations["rce"] = true

		case strings.Contains(nameLower, "node") || strings.Contains(nameLower, "express") ||
			strings.Contains(nameLower, "next.js"):
			recommendations["protopollution"] = true
			recommendations["sqli"] = true
			recommendations["xss"] = true

		case strings.Contains(nameLower, "wordpress"):
			recommendations["sqli"] = true
			recommendations["xss"] = true
			recommendations["lfi"] = true
			recommendations["rce"] = true

		case strings.Contains(nameLower, "drupal") || strings.Contains(nameLower, "joomla"):
			recommendations["sqli"] = true
			recommendations["xss"] = true
			recommendations["rce"] = true

		case strings.Contains(nameLower, "react") || strings.Contains(nameLower, "angular") ||
			strings.Contains(nameLower, "vue"):
			recommendations["xss"] = true
			recommendations["csti"] = true

		case catLower == "waf":
			recommendations["wafevasion"] = true

		case catLower == "cdn":
			recommendations["ssrf"] = true
			recommendations["cachepoisoning"] = true
		}
	}

	// Always include fundamental checks
	if len(stack.Components) > 0 {
		recommendations["xss"] = true
		recommendations["sqli"] = true
	}

	result := make([]string, 0, len(recommendations))
	for id := range recommendations {
		result = append(result, id)
	}
	return result
}

// canonicalKey converts a header name to HTTP canonical form (Title-Case).
func canonicalKey(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, "-")
}

// extractVersion pulls a version string like "7.4.3" from a header value such as "PHP/7.4.3".
var versionRe = regexp.MustCompile(`/(\d+(?:\.\d+)*)`)

func extractVersion(s string) string {
	m := versionRe.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}
