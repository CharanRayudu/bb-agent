package cloudsecurity

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
)

// probeGCPMetadata checks the GCP instance metadata service for credential exposure.
func probeGCPMetadata(ctx context.Context, fc *http.Client) []*base.Finding {
	var findings []*base.Finding

	targets := []struct {
		url      string
		desc     string
		critical bool
	}{
		{
			"http://metadata.google.internal/computeMetadata/v1/",
			"GCP metadata service root",
			false,
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/project/project-id",
			"GCP project ID disclosure",
			false,
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
			"GCP service account listing",
			true,
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
			"GCP default service account OAuth2 token",
			true,
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
			"GCP service account email",
			false,
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
			"GCP service account scopes",
			false,
		},
		{
			"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
			"GCP service account token via IP (169.254.169.254)",
			true,
		},
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url, nil)
		if err != nil {
			continue
		}
		// Required header for GCP metadata service
		req.Header.Set("Metadata-Flavor", "Google")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-scanner/1.0)")

		resp, err := fc.Do(req)
		if err != nil {
			continue
		}
		body := readBody(resp)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		sev := base.SeverityMedium
		if t.critical {
			sev = base.SeverityHigh
		}
		if strings.Contains(body, "access_token") || strings.Contains(body, `"token_type"`) {
			sev = base.SeverityCritical
		}

		excerpt := body
		if len(excerpt) > 300 {
			excerpt = excerpt[:300] + "..."
		}

		// Redact token values
		if strings.Contains(excerpt, "access_token") {
			if idx := strings.Index(excerpt, `"access_token" : "`); idx >= 0 {
				end := strings.Index(excerpt[idx+18:], `"`)
				if end > 10 {
					excerpt = excerpt[:idx+18] + "[REDACTED]" + excerpt[idx+18+end:]
				}
			}
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_GCP_METADATA_EXPOSED",
			URL:        t.url,
			Severity:   sev,
			Confidence: 0.95,
			Agent:      "cloudsecurity",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"description":      t.desc,
				"http_status":      resp.StatusCode,
				"has_token":        strings.Contains(body, "access_token"),
				"response_excerpt": excerpt,
				"mitre_attack":     "T1552.005 — Cloud Instance Metadata API",
				"remediation":      "Block metadata service access from workloads that don't need it using GCP metadata server access controls; use Workload Identity instead",
			},
		})
	}

	return findings
}

// probeGCSBucket checks whether a GCS bucket is publicly accessible.
func probeGCSBucket(ctx context.Context, fc *http.Client, bucketName string) []*base.Finding {
	var findings []*base.Finding

	targets := []struct {
		url  string
		desc string
	}{
		{
			"https://storage.googleapis.com/" + bucketName + "/",
			"GCS bucket public listing",
		},
		{
			"https://" + bucketName + ".storage.googleapis.com/",
			"GCS bucket virtual-hosted listing",
		},
		{
			"https://storage.googleapis.com/storage/v1/b/" + bucketName + "/o",
			"GCS JSON API bucket listing",
		},
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url, nil)
		if err != nil {
			continue
		}
		resp, err := fc.Do(req)
		if err != nil {
			continue
		}
		body := readBody(resp)
		resp.Body.Close()

		if resp.StatusCode == 200 && isGCSListingResponse(body) {
			excerpt := body
			if len(excerpt) > 400 {
				excerpt = excerpt[:400] + "..."
			}
			findings = append(findings, &base.Finding{
				Type:       "CLOUD_GCS_PUBLIC_BUCKET",
				URL:        t.url,
				Severity:   base.SeverityHigh,
				Confidence: 0.95,
				Agent:      "cloudsecurity",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"bucket_name":      bucketName,
					"description":      t.desc,
					"http_status":      resp.StatusCode,
					"response_excerpt": excerpt,
					"mitre_attack":     "T1530 — Data from Cloud Storage Object",
					"remediation":      "Enable uniform bucket-level access and remove allUsers/allAuthenticatedUsers IAM bindings",
				},
			})
			break
		}
	}

	return findings
}

// inferGCSBucketNames derives likely GCS bucket names from a target domain.
func inferGCSBucketNames(host string) []string {
	// GCS buckets can be domain-named (e.g. assets.example.com maps to assets.example.com bucket)
	base := strings.ToLower(strings.TrimPrefix(host, "www."))
	parts := strings.SplitN(base, ".", 2)
	root := parts[0]

	candidates := []string{
		host, // exact domain match (common GCS pattern)
		base,
		root,
		root + "-assets",
		root + "-static",
		root + "-uploads",
		root + "-backups",
		"assets." + base,
		"static." + base,
		"media." + base,
	}
	return candidates
}
