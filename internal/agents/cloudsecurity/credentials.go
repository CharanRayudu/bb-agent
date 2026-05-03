package cloudsecurity

import (
	"regexp"
	"strings"
)

// credentialPattern describes a cloud credential pattern to scan for.
type credentialPattern struct {
	name     string
	provider string
	severity string
	regex    *regexp.Regexp
}

var credPatterns = []credentialPattern{
	{
		name: "AWS Access Key ID", provider: "aws", severity: "critical",
		regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		name: "AWS Secret Access Key", provider: "aws", severity: "critical",
		regex: regexp.MustCompile(`(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key["'\s:=]+([A-Za-z0-9/+=]{40})`),
	},
	{
		name: "AWS Session Token", provider: "aws", severity: "critical",
		regex: regexp.MustCompile(`(?i)aws[_\-\s]?session[_\-\s]?token["'\s:=]+([A-Za-z0-9/+=]{100,})`),
	},
	{
		name: "GCP OAuth2 Token", provider: "gcp", severity: "critical",
		regex: regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]+`),
	},
	{
		name: "GCP API Key", provider: "gcp", severity: "high",
		regex: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	},
	{
		name: "GCP Service Account Key", provider: "gcp", severity: "critical",
		regex: regexp.MustCompile(`"type":\s*"service_account"`),
	},
	{
		name: "Azure SAS Token", provider: "azure", severity: "critical",
		regex: regexp.MustCompile(`(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=&sp=`),
	},
	{
		name: "Azure Storage Key", provider: "azure", severity: "critical",
		regex: regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{88}`),
	},
	{
		name: "Azure Client Secret", provider: "azure", severity: "critical",
		regex: regexp.MustCompile(`(?i)client[_\-]?secret["'\s:=]+([A-Za-z0-9~_\-.]{34,})`),
	},
	{
		name: "Kubernetes Service Account Token", provider: "k8s", severity: "critical",
		regex: regexp.MustCompile(`eyJhbGciOiJSUzI1NiIsImtpZCI6`),
	},
	{
		name: "AWS IAM Role ARN", provider: "aws", severity: "medium",
		regex: regexp.MustCompile(`arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/\-]+`),
	},
	{
		name: "AWS Account ID", provider: "aws", severity: "low",
		regex: regexp.MustCompile(`\b\d{12}\b`),
	},
}

// scanForCredentials scans a response body for cloud credential patterns.
func scanForCredentials(body string) []credentialMatch {
	var matches []credentialMatch
	for _, p := range credPatterns {
		found := p.regex.FindString(body)
		if found == "" {
			continue
		}
		// Redact the actual credential value for safe logging
		redacted := redactCredential(found, p.name)
		matches = append(matches, credentialMatch{
			Pattern:  p.name,
			Provider: p.provider,
			Severity: p.severity,
			Redacted: redacted,
		})
	}
	return matches
}

type credentialMatch struct {
	Pattern  string
	Provider string
	Severity string
	Redacted string
}

func redactCredential(value, name string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	// Show first 4 + last 4, mask the middle
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// isS3ListingResponse detects S3 directory listing responses.
func isS3ListingResponse(body string) bool {
	return strings.Contains(body, "<ListBucketResult") ||
		strings.Contains(body, "<Contents>") ||
		strings.Contains(body, "xmlns=\"http://s3.amazonaws.com") ||
		strings.Contains(body, "ListBucketResult")
}

// isGCSListingResponse detects GCS bucket listing responses.
func isGCSListingResponse(body string) bool {
	return strings.Contains(body, `"kind": "storage#objects"`) ||
		strings.Contains(body, `"kind":"storage#objects"`) ||
		strings.Contains(body, `"items"`) && strings.Contains(body, `"bucket"`)
}
