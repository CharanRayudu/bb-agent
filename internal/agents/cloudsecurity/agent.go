// Package cloudsecurity implements the Cloud Security specialist agent.
//
// Unlike the existing cloudhunter (which generates 0.0-confidence stubs),
// this agent performs real HTTP probes against cloud infrastructure:
//
//   - AWS: IMDS v1 credential theft, S3 public bucket listing, IAM credential
//     exposure, Terraform state files, exposed AWS config files
//   - Azure: IMDS MSI token theft, Azure AD tenant enumeration, Blob Storage
//     public container listing
//   - GCP: Metadata service OAuth2 token theft, GCS public bucket listing
//   - Cross-cloud: credential pattern scanning (AKIA*, ya29.*, AIza*, SAS),
//     Kubernetes service account token exposure
package cloudsecurity

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for cloud security testing.
type Agent struct {
	systemPrompt string
}

// New creates a new cloud security specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Cloud Security Agent" }
func (a *Agent) ID() string           { return "cloudsecurity" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem processes a cloud security work item.
// Payload keys:
//
//	"target"   — base URL of the target (required)
//	"provider" — "aws" | "azure" | "gcp" | "auto" (default: "auto")
//	"mode"     — "imds" | "storage" | "credentials" | "full" (default: "full")
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	provider, _ := item.Payload["provider"].(string)
	mode, _ := item.Payload["mode"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}
	if provider == "" {
		provider = "auto"
	}
	if mode == "" {
		mode = "full"
	}

	fc := newHTTPClient()
	host := extractHost(targetURL)

	var allFindings []*base.Finding

	switch mode {
	case "imds":
		allFindings = append(allFindings, a.runIMDSProbes(ctx, fc)...)
	case "storage":
		allFindings = append(allFindings, a.runStorageProbes(ctx, fc, host, provider)...)
	case "credentials":
		allFindings = append(allFindings, a.runCredentialProbes(ctx, fc, targetURL)...)
	default: // "full"
		allFindings = append(allFindings, a.runIMDSProbes(ctx, fc)...)
		allFindings = append(allFindings, a.runStorageProbes(ctx, fc, host, provider)...)
		allFindings = append(allFindings, a.runCredentialProbes(ctx, fc, targetURL)...)
		allFindings = append(allFindings, a.runKubernetesProbes(ctx, fc, targetURL)...)
	}

	return allFindings, nil
}

// runIMDSProbes fires metadata service probes for all three major cloud providers.
func (a *Agent) runIMDSProbes(ctx context.Context, fc *http.Client) []*base.Finding {
	var findings []*base.Finding

	// AWS IMDS (IMDSv1 — no token required)
	findings = append(findings, probeAWSIMDS(ctx, fc)...)

	select {
	case <-ctx.Done():
		return findings
	default:
	}

	// Azure IMDS
	findings = append(findings, probeAzureIMDS(ctx, fc)...)

	select {
	case <-ctx.Done():
		return findings
	default:
	}

	// GCP Metadata Service
	findings = append(findings, probeGCPMetadata(ctx, fc)...)

	return findings
}

// runStorageProbes checks cloud object storage for public access.
func (a *Agent) runStorageProbes(ctx context.Context, fc *http.Client, host, provider string) []*base.Finding {
	var findings []*base.Finding

	// AWS S3
	if provider == "aws" || provider == "auto" {
		for _, bucket := range inferS3BucketNames(host) {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			findings = append(findings, probeS3Bucket(ctx, fc, bucket)...)
		}
	}

	// GCP GCS
	if provider == "gcp" || provider == "auto" {
		for _, bucket := range inferGCSBucketNames(host) {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			findings = append(findings, probeGCSBucket(ctx, fc, bucket)...)
		}
	}

	// Azure Blob Storage
	if provider == "azure" || provider == "auto" {
		storageAccounts := inferAzureStorageAccounts(host)
		for _, acct := range storageAccounts {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			findings = append(findings, probeAzureStorage(ctx, fc, acct)...)
		}

		// Azure AD enumeration using the target domain
		findings = append(findings, probeAzureAD(ctx, fc, host)...)
	}

	return findings
}

// runCredentialProbes scans the target web application for exposed cloud credentials.
func (a *Agent) runCredentialProbes(ctx context.Context, fc *http.Client, targetURL string) []*base.Finding {
	var findings []*base.Finding

	// AWS config/credential files
	findings = append(findings, probeAWSExposed(ctx, fc, targetURL)...)

	// Scan common paths for credential patterns
	sensitiveFiles := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.backup",
		"/config.json", "/config.yml", "/config.yaml",
		"/application.yml", "/application.properties",
		"/secrets.json", "/secrets.yml",
		"/docker-compose.yml", "/docker-compose.yaml",
		"/.github/workflows/deploy.yml",
		"/Makefile",
		"/package.json",
	}

	prefix := strings.TrimRight(targetURL, "/")
	for _, path := range sensitiveFiles {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		u := prefix + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := fc.Do(req)
		if err != nil {
			continue
		}
		body := readBody(resp)
		resp.Body.Close()

		if resp.StatusCode != 200 || len(body) < 10 {
			continue
		}

		matches := scanForCredentials(body)
		if len(matches) == 0 {
			continue
		}

		for _, m := range matches {
			findings = append(findings, &base.Finding{
				Type:       "CLOUD_CREDENTIAL_LEAK",
				URL:        u,
				Severity:   m.Severity,
				Confidence: 0.88,
				Agent:      a.ID(),
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"file_path":        path,
					"credential_type":  m.Pattern,
					"cloud_provider":   m.Provider,
					"redacted_value":   m.Redacted,
					"http_status":      resp.StatusCode,
					"mitre_attack":     "T1552.001 — Credentials In Files",
					"remediation":      "Remove credentials from source code/config files, use secrets managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager), rotate exposed credentials immediately",
				},
			})
		}
	}

	return findings
}

// runKubernetesProbes checks for Kubernetes-specific cloud credential exposure.
func (a *Agent) runKubernetesProbes(ctx context.Context, fc *http.Client, targetURL string) []*base.Finding {
	var findings []*base.Finding

	k8sPaths := []struct {
		path string
		desc string
		sev  string
	}{
		{"/api/v1/namespaces/default/secrets", "K8s secrets API unauthenticated access", "critical"},
		{"/api/v1/namespaces/kube-system/secrets", "K8s system secrets API", "critical"},
		{"/api/v1/pods", "K8s pod listing without auth", "high"},
		{"/api/v1/nodes", "K8s node listing", "medium"},
		{"/.kube/config", "Exposed kubeconfig file", "critical"},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", "K8s SA token direct exposure", "critical"},
	}

	prefix := strings.TrimRight(targetURL, "/")
	for _, p := range k8sPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		u := prefix + p.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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

		// Verify it looks like actual K8s API response
		if !strings.Contains(body, `"kind"`) && !strings.Contains(body, "apiVersion") &&
			!strings.Contains(body, "eyJhbGci") { // JWT token prefix
			continue
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_K8S_UNAUTHENTICATED",
			URL:        u,
			Severity:   p.sev,
			Confidence: 0.90,
			Agent:      a.ID(),
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"path":         p.path,
				"description":  p.desc,
				"http_status":  resp.StatusCode,
				"mitre_attack": "T1613 — Container and Resource Discovery",
				"remediation":  "Enable Kubernetes RBAC, disable anonymous API access, use network policies to restrict API server access",
			},
		})
	}

	return findings
}

// inferAzureStorageAccounts derives likely Azure storage account names from a host.
func inferAzureStorageAccounts(host string) []string {
	normalized := strings.ToLower(strings.TrimPrefix(host, "www."))
	parts := strings.SplitN(normalized, ".", 2)
	root := parts[0]
	// Azure storage account names: 3–24 lowercase alphanumeric chars
	root = strings.ReplaceAll(root, "-", "")
	if len(root) > 20 {
		root = root[:20]
	}
	return []string{
		root,
		root + "assets",
		root + "static",
		root + "storage",
		root + "data",
		root + "backup",
	}
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     15 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
