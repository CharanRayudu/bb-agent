// Package secondorder implements the Second-Order Injection specialist agent.
//
// It tests for stored/second-order injection vulnerabilities: payloads are
// stored through one endpoint and triggered (reflected/executed) via another.
package secondorder

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for second-order injection detection.
type Agent struct {
	systemPrompt string
}

// New creates a new Second-Order Injection specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Second-Order Injection Agent" }
func (a *Agent) ID() string           { return "secondorder" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// storePayloads contains the payloads used to probe stored injection.
var storePayloads = []string{
	`<img src=x onerror=alert(1)>`,
	`' OR 1=1--`,
	`{{7*7}}`,
}

// retrievalPaths are common paths where stored content surfaces.
var retrievalPaths = []string{
	"/profile",
	"/account",
	"/comments",
	"/admin",
	"/admin/users",
	"/dashboard",
	"/user",
	"/users",
	"/me",
	"/settings",
}

// ProcessItem processes a single second-order injection work item.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	fc := base.NewFuzzClient()

	// Determine form fields from payload["forms"] or fall back to common fields.
	formFields := extractFormFields(item.Payload)
	if len(formFields) == 0 {
		formFields = []string{"name", "comment", "bio", "description", "username", "message"}
	}

	// Build retrieval URLs from the base target + known path patterns.
	retrievalURLs := buildRetrievalURLs(targetURL)

	var findings []*base.Finding

	for _, field := range formFields {
		for _, payload := range storePayloads {
			// Step 1: Store the payload via POST.
			storeResult := fc.ProbePOST(ctx, targetURL, field, payload)
			if storeResult.Error != nil {
				continue
			}
			// Only pursue if the store request succeeded (2xx or 3xx).
			if storeResult.StatusCode >= 400 {
				continue
			}

			// Step 2: Probe retrieval endpoints.
			for _, rURL := range retrievalURLs {
				retrieveResult := fc.ProbeGET(ctx, rURL, "", "")
				if retrieveResult.Error != nil {
					continue
				}

				conf, vulnType := evaluateRetrieval(retrieveResult.Body, payload)
				if conf == 0 {
					continue
				}

				priority, _ := item.Payload["priority"].(string)
				findings = append(findings, &base.Finding{
					Type:       vulnType,
					URL:        rURL,
					Parameter:  field,
					Payload:    payload,
					Severity:   mapPriorityToSeverity(priority),
					Confidence: conf,
					Evidence: map[string]interface{}{
						"store_url":       targetURL,
						"retrieval_url":   rURL,
						"store_status":    storeResult.StatusCode,
						"retrieve_status": retrieveResult.StatusCode,
						"payload":         payload,
					},
					Method: "POST→GET",
				})
			}
		}
	}

	return findings, nil
}

// evaluateRetrieval checks whether the stored payload is reflected/executed in
// the retrieval response.  Returns (confidence, type) or (0, "").
func evaluateRetrieval(body, payload string) (float64, string) {
	if !base.DetectReflection(body, payload) {
		return 0, ""
	}

	// Check for XSS execution.
	if strings.Contains(payload, "<img") || strings.Contains(payload, "<script") {
		if base.DetectXSSExecution(body, payload) {
			return 0.8, "Stored XSS"
		}
		// Reflected in body but not executed.
		return 0.55, "Stored XSS (reflected, unexecuted)"
	}

	// Check for SQLi error.
	if strings.Contains(payload, "OR 1=1") || strings.Contains(payload, "'") {
		if found, dbType := base.DetectSQLError(body); found {
			return 0.75, fmt.Sprintf("Stored SQLi (%s)", dbType)
		}
		// Payload reflected but no DB error observed.
		return 0.45, "Stored SQLi (reflected)"
	}

	// Template injection: {{7*7}} → 49
	if strings.Contains(payload, "{{7*7}}") && strings.Contains(body, "49") {
		return 0.8, "Stored SSTI"
	}

	return 0.4, "Second-Order Injection (reflected)"
}

// extractFormFields reads form field names from payload["forms"] if available.
func extractFormFields(payload map[string]interface{}) []string {
	raw, ok := payload["forms"]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

// buildRetrievalURLs builds candidate retrieval URLs from the base target.
func buildRetrievalURLs(targetURL string) []string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host

	urls := make([]string, 0, len(retrievalPaths))
	for _, p := range retrievalPaths {
		urls = append(urls, base+p)
	}
	return urls
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "high"
	}
}

const defaultSystemPrompt = `You are a Second-Order Injection specialist focused on:
- Stored XSS: payloads stored in the application and executed when retrieved
- Stored SQLi: SQL fragments stored and later interpolated into queries
- Stored SSTI: template expressions stored and evaluated server-side
- Second-order command injection and path traversal

Strategy:
1. POST a payload to an input field (profile, comment, bio, etc.)
2. Retrieve the stored value via a read endpoint (profile page, admin panel, comment list)
3. Confirm execution or error in the retrieved response

Confidence thresholds:
- 0.80: Payload reflected AND executed (XSS fires, SSTI evaluates, SQLi error present)
- 0.75: Strong database error signature in retrieval response
- 0.55: Payload reflected unescaped but no execution confirmed
- 0.45: Payload reflected with minor modification

Severity: Stored XSS and Stored SQLi are always HIGH or CRITICAL.`
