package devsecops

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
)

type secretPattern struct {
	name       string
	regex      *regexp.Regexp
	severity   string
	confidence float64
}

var secretPatterns = []secretPattern{
	{
		name:       "AWS Access Key ID",
		regex:      regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		severity:   base.SeverityCritical,
		confidence: 0.97,
	},
	{
		name:       "AWS Secret Access Key",
		regex:      regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]`),
		severity:   base.SeverityCritical,
		confidence: 0.90,
	},
	{
		name:       "GitHub Personal Access Token",
		regex:      regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "GitHub OAuth Token",
		regex:      regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "GitHub App Token",
		regex:      regexp.MustCompile(`(ghs_|ghu_)[A-Za-z0-9]{36}`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "Slack Bot Token",
		regex:      regexp.MustCompile(`xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}`),
		severity:   base.SeverityHigh,
		confidence: 0.99,
	},
	{
		name:       "Slack User Token",
		regex:      regexp.MustCompile(`xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}`),
		severity:   base.SeverityHigh,
		confidence: 0.99,
	},
	{
		name:       "Google API Key",
		regex:      regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		severity:   base.SeverityHigh,
		confidence: 0.95,
	},
	{
		name:       "Google OAuth Client Secret",
		regex:      regexp.MustCompile(`(?i)google.{0,20}client.secret.{0,10}['\"]([A-Za-z0-9_\-]{24})['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.85,
	},
	{
		name:       "Stripe Secret Key",
		regex:      regexp.MustCompile(`sk_(live|test)_[A-Za-z0-9]{24,}`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "Stripe Publishable Key",
		regex:      regexp.MustCompile(`pk_(live|test)_[A-Za-z0-9]{24,}`),
		severity:   base.SeverityMedium,
		confidence: 0.99,
	},
	{
		name:       "Twilio Account SID",
		regex:      regexp.MustCompile(`AC[a-z0-9]{32}`),
		severity:   base.SeverityHigh,
		confidence: 0.85,
	},
	{
		name:       "Twilio Auth Token",
		regex:      regexp.MustCompile(`(?i)twilio.{0,20}auth.token.{0,10}['\"]([a-z0-9]{32})['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.88,
	},
	{
		name:       "SendGrid API Key",
		regex:      regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		severity:   base.SeverityHigh,
		confidence: 0.99,
	},
	{
		name:       "NPM Auth Token",
		regex:      regexp.MustCompile(`(?i)npm_[A-Za-z0-9]{36}`),
		severity:   base.SeverityHigh,
		confidence: 0.97,
	},
	{
		name:       "PyPI API Token",
		regex:      regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`),
		severity:   base.SeverityHigh,
		confidence: 0.99,
	},
	{
		name:       "RSA Private Key",
		regex:      regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "Generic Password in Config",
		regex:      regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.72,
	},
	{
		name:       "Database Connection String",
		regex:      regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|mssql):\/\/[^:]+:[^@]+@[^\s'"]+`),
		severity:   base.SeverityCritical,
		confidence: 0.93,
	},
	{
		name:       "JWT Secret",
		regex:      regexp.MustCompile(`(?i)jwt.{0,20}(secret|key)\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{16,})['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.82,
	},
	{
		name:       "Azure Storage Account Key",
		regex:      regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{88}`),
		severity:   base.SeverityCritical,
		confidence: 0.99,
	},
	{
		name:       "Azure SAS Token",
		regex:      regexp.MustCompile(`(?i)sv=20\d\d-\d\d-\d\d&s[sbt]=.{20,}&sig=[A-Za-z0-9%+/=]{40,}`),
		severity:   base.SeverityHigh,
		confidence: 0.92,
	},
	{
		name:       "Heroku API Key",
		regex:      regexp.MustCompile(`(?i)heroku.{0,20}['\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.87,
	},
	{
		name:       "Mailgun API Key",
		regex:      regexp.MustCompile(`key-[A-Za-z0-9]{32}`),
		severity:   base.SeverityHigh,
		confidence: 0.80,
	},
	{
		name:       "Docker Hub Token",
		regex:      regexp.MustCompile(`(?i)docker.{0,20}(password|token|secret).{0,10}['\"]([A-Za-z0-9_\-]{20,})['\"]`),
		severity:   base.SeverityHigh,
		confidence: 0.76,
	},
}

// sensitiveFilePaths are paths commonly containing secrets that we probe for.
var sensitiveFilePaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.backup",
	"/config/.env",
	"/config/secrets.yml",
	"/config/database.yml",
	"/config/application.yml",
	"/.git/config",
	"/wp-config.php",
	"/configuration.php",
	"/settings.py",
	"/config.py",
	"/application.properties",
	"/application.yml",
	"/application-prod.yml",
	"/secrets.json",
	"/credentials.json",
	"/.npmrc",
	"/.pypirc",
	"/docker-compose.yml",
	"/docker-compose.override.yml",
	"/Makefile",
	"/terraform.tfvars",
	"/terraform.tfstate",
	"/.terraform/terraform.tfstate",
}

func fetchAndScanSecrets(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	var findings []*base.Finding

	for _, path := range sensitiveFilePaths {
		url := strings.TrimRight(targetURL, "/") + path
		content, statusCode, err := fetchFile(ctx, client, url)
		if err != nil || statusCode != 200 || len(content) == 0 {
			continue
		}
		// Skip HTML responses (login pages, etc.)
		if looksLikeHTML(content) {
			continue
		}

		fileFindings := scanSecretsInContent(url, path, content)
		findings = append(findings, fileFindings...)

		// File is accessible but no secrets — still report the exposure
		if len(fileFindings) == 0 {
			findings = append(findings, &base.Finding{
				Type:       "Secret-FileExposure",
				URL:        url,
				Severity:   base.SeverityMedium,
				Confidence: 0.90,
				Agent:      "devsecops",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"path":        path,
					"status_code": statusCode,
					"size_bytes":  len(content),
					"note":        "Sensitive configuration file is publicly accessible",
				},
			})
		}
	}
	return findings
}

func scanSecretsInContent(sourceURL, filePath, content string) []*base.Finding {
	var findings []*base.Finding
	lines := strings.Split(content, "\n")

	for _, pat := range secretPatterns {
		for lineNum, line := range lines {
			match := pat.regex.FindString(line)
			if match == "" {
				continue
			}

			// Skip obvious test/example values
			lower := strings.ToLower(line)
			if strings.Contains(lower, "example") ||
				strings.Contains(lower, "placeholder") ||
				strings.Contains(lower, "your_") ||
				strings.Contains(lower, "insert_") ||
				strings.Contains(lower, "change_me") {
				continue
			}

			findings = append(findings, &base.Finding{
				Type:       fmt.Sprintf("Secret-%s", slugify(pat.name)),
				URL:        sourceURL,
				Severity:   pat.severity,
				Confidence: pat.confidence,
				Agent:      "devsecops",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"file":        filePath,
					"line":        lineNum + 1,
					"pattern":     pat.name,
					"match":       redactSecret(match),
					"raw_line":    redactSecretLine(line),
				},
				Payload: redactSecret(match),
			})
		}
	}
	return findings
}

func fetchFile(ctx context.Context, client *http.Client, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-scanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func looksLikeHTML(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))
	return strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") ||
		strings.Contains(lower[:min(200, len(lower))], "<head>")
}

func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func redactSecretLine(line string) string {
	if len(line) > 120 {
		line = line[:120] + "..."
	}
	// Redact anything after = or : that looks like a secret
	for _, pat := range secretPatterns {
		line = pat.regex.ReplaceAllStringFunc(line, func(m string) string {
			return redactSecret(m)
		})
	}
	return line
}

func slugify(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "/", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
