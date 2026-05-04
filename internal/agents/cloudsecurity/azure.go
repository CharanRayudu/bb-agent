package cloudsecurity

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
)

// probeAzureIMDS checks the Azure Instance Metadata Service for token exposure.
func probeAzureIMDS(ctx context.Context, fc *http.Client) []*base.Finding {
	var findings []*base.Finding

	targets := []struct {
		url  string
		desc string
	}{
		{
			"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			"Azure IMDS instance metadata",
		},
		{
			"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
			"Azure MSI OAuth2 token for management API",
		},
		{
			"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
			"Azure MSI OAuth2 token for storage",
		},
		{
			"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
			"Azure MSI OAuth2 token for Key Vault",
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
		req.Header.Set("Metadata", "true") // Required header for Azure IMDS
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

		sev := base.SeverityHigh
		if strings.Contains(body, "access_token") || strings.Contains(body, "accessToken") {
			sev = base.SeverityCritical
		}

		excerpt := body
		if len(excerpt) > 300 {
			excerpt = excerpt[:300] + "..."
		}

		// Redact any tokens
		if strings.Contains(excerpt, "access_token") {
			if idx := strings.Index(excerpt, `"access_token":"`); idx >= 0 {
				end := strings.Index(excerpt[idx+16:], `"`)
				if end > 0 && end > 10 {
					excerpt = excerpt[:idx+16] + "[REDACTED]" + excerpt[idx+16+end:]
				}
			}
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_AZURE_IMDS_EXPOSED",
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
				"remediation":      "Restrict IMDS access using Azure network policies; use managed identity with minimal permissions",
			},
		})
	}

	return findings
}

// probeAzureAD enumerates Azure AD tenant information via public endpoints.
func probeAzureAD(ctx context.Context, fc *http.Client, domain string) []*base.Finding {
	var findings []*base.Finding

	// Azure AD tenant discovery via OpenID configuration
	targets := []struct {
		url  string
		desc string
		sev  string
	}{
		{
			"https://login.microsoftonline.com/" + domain + "/.well-known/openid-configuration",
			"Azure AD OpenID configuration — tenant ID disclosure",
			base.SeverityLow,
		},
		{
			"https://login.microsoftonline.com/" + domain + "/v2.0/.well-known/openid-configuration",
			"Azure AD v2 OpenID configuration",
			base.SeverityLow,
		},
		{
			"https://login.microsoftonline.com/common/userrealm/" + domain + "?api-version=2.1",
			"Azure AD user realm — federated vs. managed tenant discovery",
			base.SeverityInfo,
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

		if resp.StatusCode != 200 {
			continue
		}

		// Only report if we got meaningful tenant data
		if !strings.Contains(body, "tenant") && !strings.Contains(body, "issuer") {
			continue
		}

		excerpt := body
		if len(excerpt) > 400 {
			excerpt = excerpt[:400] + "..."
		}

		// Extract tenant ID if present
		tenantID := ""
		if idx := strings.Index(body, `"tid":"`); idx >= 0 {
			end := strings.Index(body[idx+7:], `"`)
			if end > 0 {
				tenantID = body[idx+7 : idx+7+end]
			}
		}

		ev := map[string]interface{}{
			"domain":           domain,
			"description":      t.desc,
			"http_status":      resp.StatusCode,
			"response_excerpt": excerpt,
			"mitre_attack":     "T1087.004 — Account Discovery: Cloud Account",
			"remediation":      "Tenant ID disclosure is informational but aids further Azure AD attacks; enforce conditional access policies",
		}
		if tenantID != "" {
			ev["tenant_id"] = tenantID
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_AZURE_AD_ENUM",
			URL:        t.url,
			Severity:   t.sev,
			Confidence: 0.80,
			Agent:      "cloudsecurity",
			Timestamp:  time.Now(),
			Evidence:   ev,
		})
	}

	return findings
}

// probeAzureStorage checks for publicly accessible Azure Blob Storage containers.
func probeAzureStorage(ctx context.Context, fc *http.Client, storageAccount string) []*base.Finding {
	var findings []*base.Finding

	// Common container names to probe
	containers := []string{
		"$web", "public", "assets", "static", "uploads", "backups",
		"data", "logs", "images", "files", "media", "documents",
	}

	for _, container := range containers {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := "https://" + storageAccount + ".blob.core.windows.net/" + container + "?restype=container&comp=list"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := fc.Do(req)
		if err != nil {
			continue
		}
		body := readBody(resp)
		resp.Body.Close()

		if resp.StatusCode == 200 && strings.Contains(body, "<EnumerationResults") {
			excerpt := body
			if len(excerpt) > 400 {
				excerpt = excerpt[:400] + "..."
			}
			findings = append(findings, &base.Finding{
				Type:       "CLOUD_AZURE_BLOB_PUBLIC",
				URL:        url,
				Severity:   base.SeverityHigh,
				Confidence: 0.95,
				Agent:      "cloudsecurity",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"storage_account":  storageAccount,
					"container":        container,
					"http_status":      resp.StatusCode,
					"response_excerpt": excerpt,
					"mitre_attack":     "T1530 — Data from Cloud Storage Object",
					"remediation":      "Set container access level to Private; use Azure AD authentication for all storage access",
				},
			})
		}
	}

	return findings
}
