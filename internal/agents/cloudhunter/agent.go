// Package cloudhunter implements the Cloud Hunter specialist agent.
// Deep-dives into cloud-specific misconfigurations: S3 buckets, IAM roles,
// cloud metadata endpoints, serverless function leaks, and cloud-native APIs.
package cloudhunter

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Cloud Hunter Agent" }
func (a *Agent) ID() string           { return "cloudhunter" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Detect cloud provider from infrastructure hints
	infra, _ := item.Payload["infrastructure"].(string)
	provider := detectProvider(infra, targetURL)

	var findings []*base.Finding
	tests := getTestsForProvider(provider)
	for _, tc := range tests {
		findings = append(findings, &base.Finding{
			Type:       "Cloud Misconfiguration",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"provider": provider,
				"category": tc.category,
				"impact":   tc.impact,
				"cwe":      tc.cwe,
			},
			Method: tc.method,
		})
	}
	return findings, nil
}

func detectProvider(infra, url string) string {
	combined := strings.ToLower(infra + " " + url)
	if strings.Contains(combined, "aws") || strings.Contains(combined, "amazonaws") || strings.Contains(combined, "s3") {
		return "aws"
	}
	if strings.Contains(combined, "gcp") || strings.Contains(combined, "google") || strings.Contains(combined, "googleapis") {
		return "gcp"
	}
	if strings.Contains(combined, "azure") || strings.Contains(combined, "microsoft") || strings.Contains(combined, "blob.core") {
		return "azure"
	}
	return "multi" // Test all providers
}

type cloudTest struct {
	payload  string
	category string
	severity string
	impact   string
	method   string
	cwe      string
}

func getTestsForProvider(provider string) []cloudTest {
	var tests []cloudTest

	// Universal tests
	tests = append(tests,
		cloudTest{"http://169.254.169.254/latest/meta-data/", "IMDS", "critical", "Cloud credential theft via metadata service", "GET", "CWE-918"},
		cloudTest{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "IAM Creds", "critical", "IAM role credential extraction", "GET", "CWE-918"},
		cloudTest{"http://169.254.170.2/v2/credentials/", "ECS Metadata", "critical", "ECS task credential extraction", "GET", "CWE-918"},
		cloudTest{"http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", "critical", "GCP instance metadata access", "GET", "CWE-918"},
		cloudTest{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", "critical", "Azure instance metadata access", "GET", "CWE-918"},
	)

	// AWS-specific
	if provider == "aws" || provider == "multi" {
		tests = append(tests,
			cloudTest{"Check S3 bucket ACL: s3api get-bucket-acl", "S3 Permissions", "high", "Public S3 bucket access", "GET", "CWE-732"},
			cloudTest{"List S3 objects without auth", "S3 Listing", "high", "Unauthenticated S3 bucket listing", "GET", "CWE-284"},
			cloudTest{"PUT object to S3 bucket without auth", "S3 Write", "critical", "Unauthenticated S3 write access", "PUT", "CWE-284"},
			cloudTest{"Check for .env files in S3 bucket", "S3 Secrets", "critical", "Secrets exposed in S3", "GET", "CWE-200"},
			cloudTest{"Probe Lambda function URLs for auth bypass", "Lambda Auth", "high", "Unauthenticated Lambda invocation", "POST", "CWE-306"},
			cloudTest{"Check CloudFront origin misconfiguration", "CDN Bypass", "medium", "CloudFront origin direct access", "GET", "CWE-284"},
			cloudTest{"STS GetCallerIdentity for role enumeration", "IAM Enum", "medium", "IAM role enumeration via STS", "POST", "CWE-200"},
			cloudTest{"SNS topic policy: check for wildcard (*) principal", "SNS Perms", "high", "Public SNS topic", "GET", "CWE-732"},
			cloudTest{"SQS queue policy: check for wildcard (*) principal", "SQS Perms", "high", "Public SQS queue", "GET", "CWE-732"},
		)
	}

	// GCP-specific
	if provider == "gcp" || provider == "multi" {
		tests = append(tests,
			cloudTest{"List GCS objects without auth: storage.googleapis.com/{bucket}", "GCS Listing", "high", "Unauthenticated GCS bucket listing", "GET", "CWE-284"},
			cloudTest{"Check Firebase Realtime Database: {project}.firebaseio.com/.json", "Firebase", "critical", "Unauthenticated Firebase access", "GET", "CWE-306"},
			cloudTest{"Check Firestore: firestore.googleapis.com/v1/projects/{project}/databases", "Firestore", "high", "Unauthenticated Firestore access", "GET", "CWE-306"},
			cloudTest{"Cloud Function invocation without auth", "Cloud Functions", "high", "Unauthenticated Cloud Function", "POST", "CWE-306"},
			cloudTest{"Check GCP service account key in source", "SA Key Leak", "critical", "Service account key in client code", "GET", "CWE-798"},
		)
	}

	// Azure-specific
	if provider == "azure" || provider == "multi" {
		tests = append(tests,
			cloudTest{"List Blob Storage without auth: blob.core.windows.net/{container}?restype=container&comp=list", "Blob Listing", "high", "Unauthenticated Blob Storage listing", "GET", "CWE-284"},
			cloudTest{"Check Azure Functions auth: /api/{function}?code=", "Functions Auth", "high", "Azure Function key in URL", "GET", "CWE-798"},
			cloudTest{"Azure AD tenant ID enumeration", "AD Enum", "medium", "Azure AD tenant discovery", "GET", "CWE-200"},
			cloudTest{"Check Azure Key Vault for public endpoints", "Key Vault", "critical", "Key Vault accessible without auth", "GET", "CWE-306"},
		)
	}

	return tests
}

const defaultSystemPrompt = `You are a Cloud Infrastructure Security Specialist:

AWS Expertise:
- S3 bucket permissions, ACLs, and bucket policies
- IAM role assumption, credential extraction from IMDS
- Lambda function URL authentication bypass
- CloudFront origin misconfiguration
- SNS/SQS wildcard principal policies

GCP Expertise:
- GCS bucket listing and public access
- Firebase/Firestore unauthenticated access
- Cloud Function invocation without auth
- Service account key exposure
- GKE RBAC misconfiguration

Azure Expertise:
- Blob Storage container listing
- Azure Functions authentication keys in URLs
- Azure AD tenant enumeration
- Key Vault public endpoint exposure

Cloud-Agnostic:
- IMDS/metadata service access (169.254.169.254)
- Serverless function auth bypass
- Cloud SDK configuration leaks (.aws/credentials, gcloud, az profiles)

RULES:
1. Cloud credential theft is ALWAYS critical
2. Public storage bucket access is HIGH-CRITICAL
3. Metadata service access confirms SSRF to critical
4. Map each finding to CWE and cloud-native controls`
