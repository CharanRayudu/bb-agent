// Package s3enum implements the S3/Cloud Storage enumeration specialist agent.
//
// Discovers publicly accessible cloud storage buckets (AWS S3, GCS, Azure Blob)
// and common sensitive file exposures (.git, .env, backup files) on targets.
package s3enum

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for S3/cloud storage enumeration.
type Agent struct {
	systemPrompt string
}

// New creates a new S3/Cloud Storage specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "S3/Cloud Storage Agent" }
func (a *Agent) ID() string           { return "s3enum" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// bucketSuffixes are common bucket name permutations derived from a base domain name.
var bucketSuffixes = []string{
	"",
	"-backup",
	"-dev",
	"-prod",
	"-assets",
	"-data",
	"-files",
	"-uploads",
	"-static",
	"-public",
}

// commonExposures are well-known sensitive paths to check on the target itself.
var commonExposures = []struct {
	path      string
	marker    string // substring that confirms exposure
	vulnType  string
	severity  string
	confidence float64
}{
	{"/.git/HEAD", "ref: refs/heads/", "Git Repository Exposure", "high", 0.7},
	{"/.env", "DB_PASSWORD", "Environment File Exposure", "critical", 0.9},
	{"/.env", "APP_KEY=", "Environment File Exposure", "critical", 0.9},
	{"/.env", "SECRET", "Environment File Exposure", "critical", 0.85},
	{"/backup.zip", "", "Backup Archive Exposure", "high", 0.7},
	{"/dump.sql", "INSERT INTO", "Database Dump Exposure", "critical", 0.9},
	{"/dump.sql", "CREATE TABLE", "Database Dump Exposure", "critical", 0.9},
}

// extractBaseName extracts the primary domain label from a URL (e.g. "example.com" → "example").
func extractBaseName(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	// Strip port if present.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	// Take the second-to-last label as the "company" name (foo.example.com → example, example.com → example).
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}

// newHTTPClient returns an insecure TLS HTTP client that follows no redirects.
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// get performs a GET and returns (statusCode, body, error).
func get(ctx context.Context, client *http.Client, u string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(b), nil
}

// ProcessItem enumerates cloud storage and common file exposures for the target.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	baseName := extractBaseName(targetURL)
	if baseName == "" {
		return nil, fmt.Errorf("could not extract domain base name from %s", targetURL)
	}

	client := newHTTPClient()
	var findings []*base.Finding

	// --- Cloud bucket enumeration ---
	for _, suffix := range bucketSuffixes {
		bucket := baseName + suffix

		// AWS S3
		awsURL := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
		code, body, err := get(ctx, client, awsURL)
		if err == nil {
			switch code {
			case http.StatusOK:
				if strings.Contains(body, "<ListBucketResult") {
					findings = append(findings, &base.Finding{
						Type:       "Exposed S3 Bucket (Public Listing)",
						URL:        awsURL,
						Parameter:  "bucket",
						Payload:    bucket,
						Severity:   "critical",
						Confidence: 0.95,
						Evidence: map[string]interface{}{
							"bucket":    bucket,
							"provider":  "aws",
							"status":    code,
							"body_hint": truncate(body, 200),
						},
						Method: "GET",
					})
				}
			case http.StatusForbidden:
				findings = append(findings, &base.Finding{
					Type:       "S3 Bucket Exists (Private)",
					URL:        awsURL,
					Parameter:  "bucket",
					Payload:    bucket,
					Severity:   "info",
					Confidence: 0.7,
					Evidence: map[string]interface{}{
						"bucket":   bucket,
						"provider": "aws",
						"status":   code,
						"note":     "bucket exists but is not publicly readable",
					},
					Method: "GET",
				})
			}
		}

		// Google Cloud Storage
		gcsURL := fmt.Sprintf("https://storage.googleapis.com/%s/", bucket)
		code, body, err = get(ctx, client, gcsURL)
		if err == nil && code == http.StatusOK {
			if strings.Contains(body, "<ListBucketResult") || strings.Contains(body, "<Contents>") {
				findings = append(findings, &base.Finding{
					Type:       "Exposed GCS Bucket (Public Listing)",
					URL:        gcsURL,
					Parameter:  "bucket",
					Payload:    bucket,
					Severity:   "critical",
					Confidence: 0.95,
					Evidence: map[string]interface{}{
						"bucket":    bucket,
						"provider":  "gcs",
						"status":    code,
						"body_hint": truncate(body, 200),
					},
					Method: "GET",
				})
			}
		}

		// Azure Blob Storage
		azureURL := fmt.Sprintf("https://%s.blob.core.windows.net/$web/", bucket)
		code, body, err = get(ctx, client, azureURL)
		if err == nil && code == http.StatusOK {
			findings = append(findings, &base.Finding{
				Type:       "Exposed Azure Blob Container",
				URL:        azureURL,
				Parameter:  "container",
				Payload:    bucket,
				Severity:   "critical",
				Confidence: 0.95,
				Evidence: map[string]interface{}{
					"bucket":    bucket,
					"provider":  "azure",
					"status":    code,
					"body_hint": truncate(body, 200),
				},
				Method: "GET",
			})
		}
	}

	// --- Common file/directory exposures on the target itself ---
	baseTarget := strings.TrimRight(targetURL, "/")
	// Strip path — we want origin only.
	if u, err := url.Parse(targetURL); err == nil {
		baseTarget = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	for _, exp := range commonExposures {
		checkURL := baseTarget + exp.path
		code, body, err := get(ctx, client, checkURL)
		if err != nil || code != http.StatusOK {
			continue
		}

		conf := exp.confidence
		if exp.marker != "" && !strings.Contains(body, exp.marker) {
			// Body doesn't contain the expected marker; lower confidence.
			conf = 0.4
		}

		if conf < 0.4 {
			continue
		}

		findings = append(findings, &base.Finding{
			Type:       exp.vulnType,
			URL:        checkURL,
			Parameter:  "path",
			Payload:    exp.path,
			Severity:   exp.severity,
			Confidence: conf,
			Evidence: map[string]interface{}{
				"status":    code,
				"marker":    exp.marker,
				"body_hint": truncate(body, 200),
			},
			Method: "GET",
		})
	}

	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

const defaultSystemPrompt = `You are an S3 and cloud storage enumeration specialist.

Strategy:
1. Derive bucket name candidates from the target domain (company, company-backup, company-dev, etc.)
2. Check AWS S3: GET https://{bucket}.s3.amazonaws.com/ — 200 + <ListBucketResult = public listing (CRITICAL)
3. Check GCS:   GET https://storage.googleapis.com/{bucket}/
4. Check Azure: GET https://{bucket}.blob.core.windows.net/$web/
5. Check sensitive exposures on the target: /.git/HEAD, /.env, /backup.zip, /dump.sql

Severity:
- Public bucket listing: CRITICAL (0.95)
- Private bucket exists (403): INFO (0.7)
- .git/HEAD exposure: HIGH (0.7)
- .env / dump.sql: CRITICAL (0.9)`
