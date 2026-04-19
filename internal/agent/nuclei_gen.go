package agent

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// GenerateNucleiTemplate converts a confirmed Finding into a Nuclei v3 YAML template.
func GenerateNucleiTemplate(f *Finding) string {
	id := nucleiTemplateID(f)
	name := fmt.Sprintf("%s - %s", f.Type, sanitizeNucleiString(f.URL))
	severity := strings.ToLower(strings.TrimSpace(f.Severity))
	if severity == "" {
		severity = "medium"
	}

	tags := nucleiTags(f.Type)
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}

	path := nucleiPath(f.URL, f.Parameter, f.Payload, method)
	matchers := nucleiMatchers(f)

	var sb strings.Builder
	sb.WriteString("id: " + id + "\n\n")
	sb.WriteString("info:\n")
	sb.WriteString("  name: \"" + sanitizeNucleiString(name) + "\"\n")
	sb.WriteString("  author: mirage\n")
	sb.WriteString("  severity: " + severity + "\n")
	sb.WriteString("  description: |\n")
	sb.WriteString("    Confirmed " + f.Type + " vulnerability found at " + f.URL + ".\n")
	sb.WriteString("    Payload: " + sanitizeNucleiString(f.Payload) + "\n")
	sb.WriteString("  tags: " + tags + "\n")
	sb.WriteString("  metadata:\n")
	sb.WriteString("    confidence: " + fmt.Sprintf("%.2f", f.Confidence) + "\n")
	if f.Parameter != "" {
		sb.WriteString("    parameter: \"" + sanitizeNucleiString(f.Parameter) + "\"\n")
	}
	sb.WriteString("\n")

	sb.WriteString("http:\n")
	sb.WriteString("  - method: " + method + "\n")
	sb.WriteString("    path:\n")
	for _, p := range path {
		sb.WriteString("      - \"" + p + "\"\n")
	}

	// Add body for POST requests.
	if method == "POST" && f.Parameter != "" && f.Payload != "" {
		sb.WriteString("    body: \"" + url.QueryEscape(f.Parameter) + "=" + url.QueryEscape(f.Payload) + "\"\n")
		sb.WriteString("    headers:\n")
		sb.WriteString("      Content-Type: application/x-www-form-urlencoded\n")
	}

	sb.WriteString("    matchers-condition: or\n")
	sb.WriteString("    matchers:\n")
	for _, m := range matchers {
		sb.WriteString(m)
	}

	return sb.String()
}

// nucleiTemplateID generates a URL-safe template ID from the finding.
func nucleiTemplateID(f *Finding) string {
	vulnType := strings.ToLower(strings.TrimSpace(f.Type))
	vulnType = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(vulnType, "-")
	vulnType = strings.Trim(vulnType, "-")

	var host string
	if u, err := url.Parse(f.URL); err == nil {
		host = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(u.Hostname()), "-")
		host = strings.Trim(host, "-")
	}

	if host != "" {
		return fmt.Sprintf("mirage-%s-%s", vulnType, host)
	}
	return fmt.Sprintf("mirage-%s", vulnType)
}

// nucleiTags returns a comma-separated tag string for the template.
func nucleiTags(vulnType string) string {
	key := strings.ToLower(strings.TrimSpace(vulnType))
	tags := []string{"mirage"}

	switch {
	case strings.Contains(key, "xss"):
		tags = append(tags, "xss", "owasp")
	case strings.Contains(key, "sqli") || strings.Contains(key, "sql injection"):
		tags = append(tags, "sqli", "owasp")
	case strings.Contains(key, "ssrf"):
		tags = append(tags, "ssrf", "owasp")
	case strings.Contains(key, "lfi") || strings.Contains(key, "local file"):
		tags = append(tags, "lfi", "traversal")
	case strings.Contains(key, "rce") || strings.Contains(key, "remote code"):
		tags = append(tags, "rce", "owasp")
	case strings.Contains(key, "ssti") || strings.Contains(key, "template injection"):
		tags = append(tags, "ssti", "injection")
	case strings.Contains(key, "xxe"):
		tags = append(tags, "xxe", "owasp")
	case strings.Contains(key, "idor"):
		tags = append(tags, "idor", "owasp")
	case strings.Contains(key, "jwt"):
		tags = append(tags, "jwt", "auth")
	case strings.Contains(key, "file upload"):
		tags = append(tags, "fileupload", "rce")
	case strings.Contains(key, "open redirect"):
		tags = append(tags, "redirect", "owasp")
	case strings.Contains(key, "cors"):
		tags = append(tags, "cors", "misconfiguration")
	case strings.Contains(key, "csrf"):
		tags = append(tags, "csrf", "owasp")
	case strings.Contains(key, "log4shell"):
		tags = append(tags, "log4shell", "cve", "rce")
	default:
		tags = append(tags, "generic")
	}

	return strings.Join(tags, ",")
}

// nucleiPath generates the path entries for the HTTP request section.
func nucleiPath(targetURL, param, payload, method string) []string {
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		// Fallback: use targetURL as-is.
		return []string{"{{BaseURL}}"}
	}

	base := fmt.Sprintf("{{BaseURL}}%s", u.Path)

	if method == "GET" && param != "" && payload != "" {
		q := u.Query()
		q.Set(param, payload)
		return []string{fmt.Sprintf("%s?%s", base, q.Encode())}
	}

	if u.RawQuery != "" {
		return []string{fmt.Sprintf("%s?%s", base, u.RawQuery)}
	}
	return []string{base}
}

// nucleiMatchers builds the YAML matcher blocks based on available evidence.
func nucleiMatchers(f *Finding) []string {
	var matchers []string

	// Status code matcher: look for evidence or default to 200.
	statusCode := 200
	if f.Evidence != nil {
		if sc, ok := f.Evidence["status_code"]; ok {
			switch v := sc.(type) {
			case int:
				statusCode = v
			case float64:
				statusCode = int(v)
			}
		}
	}
	matchers = append(matchers, fmt.Sprintf(
		"      - type: status\n        status:\n          - %d\n",
		statusCode,
	))

	// Word/regex matcher based on payload or evidence body content.
	words := nucleiEvidenceWords(f)
	if len(words) > 0 {
		matchers = append(matchers, buildWordMatcher(words))
	}

	return matchers
}

// nucleiEvidenceWords extracts meaningful match words from finding evidence.
func nucleiEvidenceWords(f *Finding) []string {
	var words []string
	key := strings.ToLower(strings.TrimSpace(f.Type))

	switch {
	case strings.Contains(key, "xss"):
		if f.Payload != "" {
			words = append(words, f.Payload)
		} else {
			words = append(words, "<script>alert(", "onerror=")
		}
	case strings.Contains(key, "sqli") || strings.Contains(key, "sql injection"):
		words = append(words, "you have an error in your sql", "mysql_fetch", "syntax error")
	case strings.Contains(key, "lfi") || strings.Contains(key, "local file"):
		words = append(words, "root:x:0:0", "[boot loader]", "/etc/passwd")
	case strings.Contains(key, "ssrf"):
		words = append(words, "ami-id", "instance-id", "169.254.169.254")
	case strings.Contains(key, "ssti") || strings.Contains(key, "template"):
		if f.Payload != "" {
			words = append(words, f.Payload)
		} else {
			words = append(words, "49", "7777777")
		}
	case strings.Contains(key, "rce") || strings.Contains(key, "remote code"):
		words = append(words, "uid=", "root", "/bin/sh")
	case strings.Contains(key, "xxe"):
		words = append(words, "root:x:0:0", "SYSTEM", "file://")
	}

	// Fallback: try to use evidence body.
	if len(words) == 0 && f.Evidence != nil {
		if body, ok := f.Evidence["body"].(string); ok && len(body) > 0 {
			// Take a short distinctive snippet.
			snippet := body
			if len(snippet) > 40 {
				snippet = snippet[:40]
			}
			words = append(words, snippet)
		}
	}

	return words
}

// buildWordMatcher creates a words-type matcher YAML block.
func buildWordMatcher(words []string) string {
	var sb strings.Builder
	sb.WriteString("      - type: word\n")
	sb.WriteString("        words:\n")
	for _, w := range words {
		sb.WriteString(fmt.Sprintf("          - %q\n", w))
	}
	sb.WriteString("        part: body\n")
	sb.WriteString("        condition: or\n")
	return sb.String()
}

// sanitizeNucleiString escapes characters problematic in YAML inline strings.
func sanitizeNucleiString(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
