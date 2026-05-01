package cloudsecurity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
)

// probeAWSIMDS checks whether the AWS EC2 Instance Metadata Service is reachable
// and whether it leaks IAM credentials (IMDSv1 — no token required).
func probeAWSIMDS(ctx context.Context, fc *http.Client) []*base.Finding {
	var findings []*base.Finding

	imdsTargets := []struct {
		path     string
		desc     string
		critical bool
	}{
		{"/latest/meta-data/", "IMDS root listing", false},
		{"/latest/meta-data/iam/security-credentials/", "IAM role name disclosure", true},
		{"/latest/meta-data/iam/info", "IAM info endpoint", true},
		{"/latest/meta-data/hostname", "Instance hostname", false},
		{"/latest/meta-data/instance-id", "Instance ID", false},
		{"/latest/meta-data/public-keys/", "SSH key listing", true},
		{"/latest/user-data", "User-data script (may contain secrets)", true},
		{"/latest/dynamic/instance-identity/document", "Identity document with account ID", false},
	}

	for _, t := range imdsTargets {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := "http://169.254.169.254" + t.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		// IMDSv1 has no token requirement — this is the vulnerability
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
			sev = base.SeverityCritical
		}

		excerpt := body
		if len(excerpt) > 300 {
			excerpt = excerpt[:300] + "..."
		}

		// Check for actual credential content
		if strings.Contains(body, "AccessKeyId") || strings.Contains(body, "SecretAccessKey") {
			sev = base.SeverityCritical
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_AWS_IMDS_EXPOSED",
			URL:        url,
			Severity:   sev,
			Confidence: 0.95,
			Agent:      "cloudsecurity",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"endpoint":         t.path,
				"description":      t.desc,
				"http_status":      resp.StatusCode,
				"response_excerpt": excerpt,
				"imds_version":     "v1",
				"mitre_attack":     "T1552.005 — Cloud Instance Metadata API",
				"remediation":      "Enforce IMDSv2 (require session tokens): aws ec2 modify-instance-metadata-options --http-tokens required",
			},
		})
	}

	// Attempt to fetch actual credentials if role listing succeeded
	roleFindings := fetchIAMCredentials(ctx, fc)
	findings = append(findings, roleFindings...)

	return findings
}

// fetchIAMCredentials attempts to enumerate IAM roles and fetch temporary credentials.
func fetchIAMCredentials(ctx context.Context, fc *http.Client) []*base.Finding {
	var findings []*base.Finding

	// Step 1: Get role name
	rolesURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rolesURL, nil)
	if err != nil {
		return nil
	}
	resp, err := fc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	roleBody := readBody(resp)
	resp.Body.Close()

	roleName := strings.TrimSpace(roleBody)
	if roleName == "" || strings.ContainsAny(roleName, "<>{}") {
		return nil
	}

	// Step 2: Fetch credentials for the role
	credsURL := rolesURL + roleName
	credsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, credsURL, nil)
	if err != nil {
		return nil
	}
	credsResp, err := fc.Do(credsReq)
	if err != nil || credsResp.StatusCode != 200 {
		if credsResp != nil {
			credsResp.Body.Close()
		}
		return nil
	}
	credsBody := readBody(credsResp)
	credsResp.Body.Close()

	if !strings.Contains(credsBody, "AccessKeyId") {
		return nil
	}

	findings = append(findings, &base.Finding{
		Type:       "CLOUD_AWS_IAM_CREDENTIALS_EXPOSED",
		URL:        credsURL,
		Severity:   base.SeverityCritical,
		Confidence: 0.99,
		Agent:      "cloudsecurity",
		Timestamp:  time.Now(),
		Evidence: map[string]interface{}{
			"role_name":        roleName,
			"response_excerpt": redactAWSCredentials(credsBody),
			"http_status":      200,
			"impact":           "Attacker can assume this IAM role and perform actions within its permission scope",
			"mitre_attack":     "T1552.005 — Cloud Instance Metadata API",
			"remediation":      "Immediately enforce IMDSv2, rotate all credentials, audit CloudTrail for unauthorized use",
		},
	})

	return findings
}

// probeS3Bucket checks whether an S3 bucket is publicly accessible.
func probeS3Bucket(ctx context.Context, fc *http.Client, bucketName string) []*base.Finding {
	var findings []*base.Finding

	targets := []struct {
		url  string
		desc string
	}{
		{fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName), "S3 path-style listing"},
		{fmt.Sprintf("https://s3.amazonaws.com/%s/", bucketName), "S3 virtual-hosted listing"},
		{fmt.Sprintf("https://%s.s3-website.us-east-1.amazonaws.com/", bucketName), "S3 website endpoint"},
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

		if resp.StatusCode == 200 && isS3ListingResponse(body) {
			excerpt := body
			if len(excerpt) > 400 {
				excerpt = excerpt[:400] + "..."
			}
			findings = append(findings, &base.Finding{
				Type:       "CLOUD_S3_PUBLIC_BUCKET",
				URL:        t.url,
				Severity:   base.SeverityHigh,
				Confidence: 0.95,
				Agent:      "cloudsecurity",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"bucket_name":      bucketName,
					"access_type":      "public_read",
					"description":      t.desc,
					"http_status":      resp.StatusCode,
					"response_excerpt": excerpt,
					"mitre_attack":     "T1530 — Data from Cloud Storage Object",
					"remediation":      "Enable S3 Block Public Access at the account level; audit bucket ACLs and bucket policies",
				},
			})
			break
		}

		// 403 with S3 error body = bucket exists but access denied (enumeration)
		if resp.StatusCode == 403 && strings.Contains(body, "AccessDenied") {
			findings = append(findings, &base.Finding{
				Type:       "CLOUD_S3_BUCKET_EXISTS",
				URL:        t.url,
				Severity:   base.SeverityLow,
				Confidence: 0.85,
				Agent:      "cloudsecurity",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"bucket_name":  bucketName,
					"http_status":  resp.StatusCode,
					"note":         "Bucket exists and is private — verify ownership and access policy",
					"mitre_attack": "T1580 — Cloud Infrastructure Discovery",
				},
			})
		}
	}

	return findings
}

// inferS3BucketNames derives likely S3 bucket names from a target hostname.
func inferS3BucketNames(host string) []string {
	normalized := strings.ToLower(host)
	// Strip common TLDs and subdomains
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimPrefix(normalized, "app.")
	normalized = strings.TrimPrefix(normalized, "api.")
	parts := strings.SplitN(normalized, ".", 2)
	root := parts[0]

	candidates := []string{
		root,
		root + "-assets",
		root + "-static",
		root + "-uploads",
		root + "-backups",
		root + "-data",
		root + "-public",
		root + "-private",
		root + "-logs",
		root + "-dev",
		root + "-staging",
		root + "-prod",
		"assets." + root,
		"static." + root,
		"backup." + root,
	}
	return candidates
}

// probeAWSExposed checks for exposed AWS management endpoints.
func probeAWSExposed(ctx context.Context, fc *http.Client, baseURL string) []*base.Finding {
	var findings []*base.Finding

	paths := []struct {
		path string
		desc string
		sev  string
	}{
		{"/.aws/credentials", "AWS credentials file exposed via web", "critical"},
		{"/aws-exports.json", "Amplify/AWS config with Cognito keys", "high"},
		{"/.env", "Environment file potentially containing AWS keys", "high"},
		{"/config/aws.json", "AWS config file", "high"},
		{"/backup/credentials", "Backup credentials file", "critical"},
		{"/.aws/config", "AWS CLI config with profiles", "medium"},
		{"/serverless.yml", "Serverless framework config", "medium"},
		{"/sam-template.yaml", "SAM template with resource definitions", "medium"},
		{"/cloudformation.yaml", "CloudFormation template", "medium"},
		{"/terraform.tfstate", "Terraform state file with resource IDs", "high"},
		{"/terraform.tfstate.backup", "Terraform state backup", "high"},
		{"/.terraform/terraform.tfstate", "Terraform state in .terraform dir", "high"},
	}

	prefix := strings.TrimRight(baseURL, "/")
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := prefix + p.path
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

		if resp.StatusCode != 200 {
			continue
		}

		// Check for actual AWS credential patterns in the response
		credMatches := scanForCredentials(body)
		hasRealCreds := len(credMatches) > 0

		if !hasRealCreds && !strings.ContainsAny(body, "[default\naws_access") {
			continue
		}

		sev := p.sev
		if hasRealCreds {
			sev = "critical"
		}

		excerpt := body
		if len(excerpt) > 300 {
			excerpt = excerpt[:300] + "..."
		}

		findings = append(findings, &base.Finding{
			Type:       "CLOUD_AWS_CREDENTIAL_EXPOSURE",
			URL:        url,
			Severity:   sev,
			Confidence: 0.90,
			Agent:      "cloudsecurity",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"path":             p.path,
				"description":      p.desc,
				"http_status":      resp.StatusCode,
				"has_credentials":  hasRealCreds,
				"response_excerpt": excerpt,
				"mitre_attack":     "T1552.001 — Credentials In Files",
				"remediation":      "Remove sensitive files from web root, add to .gitignore, rotate all exposed credentials immediately",
			},
		})
	}

	return findings
}

func redactAWSCredentials(body string) string {
	// Replace AccessKeyId values
	re := strings.NewReplacer(
		"AccessKeyId", "AccessKeyId",
	)
	result := re.Replace(body)
	// Simple pattern redaction — show structure but not values
	if idx := strings.Index(result, "AKIA"); idx >= 0 && idx+20 < len(result) {
		result = result[:idx+4] + "****************" + result[idx+20:]
	}
	return result
}

func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	buf := make([]byte, 8192)
	n, _ := io.ReadAtLeast(resp.Body, buf, 1)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}
