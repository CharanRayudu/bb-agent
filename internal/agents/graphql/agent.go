// Package graphql implements the GraphQL Security specialist agent.
//
// Tests for introspection, field suggestion leaks, batching abuse, IDOR via
// object ID traversal, authorization bypass, verbose errors, alias rate-limit
// bypass, CSRF on mutations, and nested query depth attacks.
package graphql

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for GraphQL security testing.
type Agent struct {
	systemPrompt string
}

// New creates a new GraphQL specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "GraphQL Security Agent" }
func (a *Agent) ID() string           { return "graphql" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// graphqlPaths are candidate GraphQL endpoint paths to probe.
var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/query",
	"/gql",
	"/graphql/v1",
	"/api/query",
}

// gqlClient wraps an http.Client for GraphQL requests.
type gqlClient struct {
	hc *http.Client
}

func newGQLClient() *gqlClient {
	return &gqlClient{
		hc: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type gqlResponse struct {
	statusCode int
	body       string
	headers    http.Header
	err        error
}

// sendQuery sends a GraphQL POST request with JSON body.
func (c *gqlClient) sendQuery(ctx context.Context, endpoint, query string, variables map[string]interface{}) gqlResponse {
	payload := map[string]interface{}{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	return c.sendJSON(ctx, endpoint, payload)
}

// sendJSON sends an arbitrary JSON body to the GraphQL endpoint.
func (c *gqlClient) sendJSON(ctx context.Context, endpoint string, body interface{}) gqlResponse {
	b, err := json.Marshal(body)
	if err != nil {
		return gqlResponse{err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return gqlResponse{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return gqlResponse{err: err}
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 512*1024)
	bodyBytes, _ := io.ReadAll(lr)

	return gqlResponse{
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
		headers:    resp.Header,
	}
}

// isGraphQLEndpoint checks if the endpoint responds like a GraphQL server.
func isGraphQLEndpoint(r gqlResponse) bool {
	if r.err != nil {
		return false
	}
	// Accept 200, 400 (invalid query), 401, 403 — all indicate a live endpoint
	if r.statusCode == 0 || r.statusCode == 404 || r.statusCode == 502 || r.statusCode == 503 {
		return false
	}
	lower := strings.ToLower(r.body)
	return strings.Contains(lower, "\"data\"") ||
		strings.Contains(lower, "\"errors\"") ||
		strings.Contains(lower, "graphql") ||
		strings.Contains(r.headers.Get("Content-Type"), "json")
}

// ProcessItem tests a target for GraphQL security issues.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Strip trailing slash from base URL
	base_ := strings.TrimRight(targetURL, "/")

	client := newGQLClient()
	var findings []*base.Finding

	// Discover active GraphQL endpoints
	endpoints := discoverEndpoints(ctx, client, base_)
	if len(endpoints) == 0 {
		return nil, nil // No GraphQL endpoints found
	}

	for _, endpoint := range endpoints {
		eps := runAllTests(ctx, client, endpoint)
		findings = append(findings, eps...)
	}

	return findings, nil
}

// discoverEndpoints probes candidate paths and returns responsive GraphQL endpoints.
func discoverEndpoints(ctx context.Context, client *gqlClient, base_ string) []string {
	var found []string
	// Use a lightweight introspection probe for discovery
	probe := `{"query":"{__typename}"}`

	for _, path := range graphqlPaths {
		endpoint := base_ + path
		b := []byte(probe)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

		resp, err := client.hc.Do(req)
		if err != nil {
			continue
		}
		lr := io.LimitReader(resp.Body, 8192)
		body, _ := io.ReadAll(lr)
		resp.Body.Close()

		r := gqlResponse{statusCode: resp.StatusCode, body: string(body), headers: resp.Header}
		if isGraphQLEndpoint(r) {
			found = append(found, endpoint)
		}
	}
	return found
}

// runAllTests executes all GraphQL security checks against one endpoint.
func runAllTests(ctx context.Context, client *gqlClient, endpoint string) []*base.Finding {
	var findings []*base.Finding

	// Test 1: Introspection enabled
	if f := testIntrospection(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 2: Field suggestion attack
	if f := testFieldSuggestion(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 3: Batching abuse
	if f := testBatching(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 4: Nested depth attack (DoS)
	if f := testDepthAttack(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 5: IDOR via object ID traversal
	if f := testIDOR(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 6: __typename disclosure (auth bypass indicator)
	if f := testTypenameDisclosure(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 7: Alias-based rate-limit bypass
	if f := testAliasRateLimit(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	// Test 8: Verbose error information disclosure
	if f := testVerboseErrors(ctx, client, endpoint); f != nil {
		findings = append(findings, f)
	}

	return findings
}

// testIntrospection checks if full schema introspection is enabled.
func testIntrospection(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	query := `{__schema{types{name fields{name}}}}`
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil || r.statusCode == 0 {
		return nil
	}

	lower := strings.ToLower(r.body)
	if !strings.Contains(lower, "__schema") && !strings.Contains(lower, "types") {
		return nil
	}

	// Confirm it actually returned schema data
	if strings.Contains(r.body, "\"data\"") && strings.Contains(lower, "name") {
		return &base.Finding{
			Type:       "GraphQL Introspection Enabled",
			URL:        endpoint,
			Parameter:  "query",
			Payload:    query,
			Severity:   base.SeverityMedium,
			Confidence: 0.92,
			Evidence: map[string]interface{}{
				"test":        "introspection",
				"status_code": r.statusCode,
				"body_snippet": truncate(r.body, 500),
				"description": "Full schema introspection is enabled, leaking all types, fields, and mutations",
			},
			Method: "POST",
		}
	}
	return nil
}

// testFieldSuggestion checks if invalid fields trigger "Did you mean" suggestions.
func testFieldSuggestion(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	// Send a clearly invalid field name to trigger suggestions
	query := `{user{invalidFieldXYZ123}}`
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil {
		return nil
	}

	lower := strings.ToLower(r.body)
	if strings.Contains(lower, "did you mean") || strings.Contains(lower, "suggestions") {
		return &base.Finding{
			Type:       "GraphQL Field Suggestion Information Disclosure",
			URL:        endpoint,
			Parameter:  "query",
			Payload:    query,
			Severity:   base.SeverityLow,
			Confidence: 0.88,
			Evidence: map[string]interface{}{
				"test":        "field_suggestion",
				"status_code": r.statusCode,
				"body_snippet": truncate(r.body, 500),
				"description": "GraphQL engine reveals valid field names via 'Did you mean?' suggestions",
			},
			Method: "POST",
		}
	}
	return nil
}

// testBatching checks if the server accepts and processes batch query arrays.
func testBatching(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	batch := []map[string]interface{}{
		{"query": "{__typename}"},
		{"query": "{__typename}"},
		{"query": "{__typename}"},
	}
	r := client.sendJSON(ctx, endpoint, batch)

	if r.err != nil || r.statusCode == 0 {
		return nil
	}

	// Batch accepted if response is a JSON array
	trimmed := strings.TrimSpace(r.body)
	if strings.HasPrefix(trimmed, "[") && r.statusCode == 200 {
		return &base.Finding{
			Type:       "GraphQL Batching Enabled",
			URL:        endpoint,
			Parameter:  "body",
			Payload:    `[{"query":"{__typename}"},...]`,
			Severity:   base.SeverityMedium,
			Confidence: 0.85,
			Evidence: map[string]interface{}{
				"test":        "batching",
				"status_code": r.statusCode,
				"body_snippet": truncate(r.body, 300),
				"description": "GraphQL supports query batching; can be abused for DoS or rate-limit bypass",
			},
			Method: "POST",
		}
	}
	return nil
}

// testDepthAttack sends a deeply nested query to check for depth limit enforcement.
func testDepthAttack(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	// Build a 10-level deep nested query using a common pattern
	query := `{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}`
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil {
		return nil
	}

	// If the server returns 200 with data (not an error about depth), depth limiting is absent
	if r.statusCode == 200 && strings.Contains(r.body, "\"data\"") {
		lower := strings.ToLower(r.body)
		// Absence of depth-limit errors
		if !strings.Contains(lower, "depth") && !strings.Contains(lower, "too deep") && !strings.Contains(lower, "complexity") {
			return &base.Finding{
				Type:       "GraphQL Missing Query Depth Limit",
				URL:        endpoint,
				Parameter:  "query",
				Payload:    query,
				Severity:   base.SeverityMedium,
				Confidence: 0.70,
				Evidence: map[string]interface{}{
					"test":        "depth_attack",
					"status_code": r.statusCode,
					"body_snippet": truncate(r.body, 300),
					"description": "No query depth limit detected; deeply nested queries may cause DoS",
				},
				Method: "POST",
			}
		}
	}
	return nil
}

// testIDOR probes for IDOR by querying with predictable numeric IDs.
func testIDOR(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	// Common IDOR patterns for GraphQL
	queries := []string{
		`{user(id:1){id email username}}`,
		`{node(id:"1"){id}}`,
		`{account(id:1){id balance email}}`,
		`{order(id:1){id total user{email}}}`,
	}

	for _, q := range queries {
		r := client.sendQuery(ctx, endpoint, q, nil)
		if r.err != nil {
			continue
		}
		// If we get data back (not just errors), IDOR may be present
		if r.statusCode == 200 && strings.Contains(r.body, "\"data\"") {
			lower := strings.ToLower(r.body)
			if strings.Contains(lower, "email") || strings.Contains(lower, "balance") || strings.Contains(lower, "total") {
				return &base.Finding{
					Type:       "GraphQL IDOR - Unauthorized Object Access",
					URL:        endpoint,
					Parameter:  "query",
					Payload:    q,
					Severity:   base.SeverityHigh,
					Confidence: 0.75,
					Evidence: map[string]interface{}{
						"test":        "idor",
						"status_code": r.statusCode,
						"body_snippet": truncate(r.body, 400),
						"description": "GraphQL query returned sensitive data for hardcoded ID without authentication check",
					},
					Method: "POST",
				}
			}
		}
	}
	return nil
}

// testTypenameDisclosure checks if __typename reveals internal type structure without auth.
func testTypenameDisclosure(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	query := `{__typename}`
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil || r.statusCode != 200 {
		return nil
	}

	if strings.Contains(r.body, "\"data\"") && strings.Contains(r.body, "__typename") {
		// Extract typename value
		var resp map[string]interface{}
		if err := json.Unmarshal([]byte(r.body), &resp); err == nil {
			if data, ok := resp["data"].(map[string]interface{}); ok {
				if typeName, ok := data["__typename"].(string); ok && typeName != "" {
					return &base.Finding{
						Type:       "GraphQL __typename Disclosure",
						URL:        endpoint,
						Parameter:  "query",
						Payload:    query,
						Severity:   base.SeverityInfo,
						Confidence: 0.95,
						Evidence: map[string]interface{}{
							"test":        "typename_disclosure",
							"status_code": r.statusCode,
							"typename":    typeName,
							"description": "__typename query succeeds unauthenticated, confirming GraphQL and revealing root type",
						},
						Method: "POST",
					}
				}
			}
		}
	}
	return nil
}

// testAliasRateLimit checks if aliases can be used to send many operations in one request.
func testAliasRateLimit(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	// Build a query with 10 aliases to the same field
	var aliases []string
	for i := 0; i < 10; i++ {
		aliases = append(aliases, fmt.Sprintf("q%d:__typename", i))
	}
	query := "{" + strings.Join(aliases, " ") + "}"
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil || r.statusCode == 0 {
		return nil
	}

	// If all aliases returned data, aliasing is not rate-limited
	if r.statusCode == 200 && strings.Contains(r.body, "\"q9\"") {
		return &base.Finding{
			Type:       "GraphQL Alias-Based Rate Limit Bypass",
			URL:        endpoint,
			Parameter:  "query",
			Payload:    query,
			Severity:   base.SeverityMedium,
			Confidence: 0.80,
			Evidence: map[string]interface{}{
				"test":        "alias_rate_limit",
				"status_code": r.statusCode,
				"body_snippet": truncate(r.body, 300),
				"description": "Multiple aliases in a single query bypass per-request rate limiting",
			},
			Method: "POST",
		}
	}
	return nil
}

// testVerboseErrors sends a malformed query to check for stack traces or internal paths.
func testVerboseErrors(ctx context.Context, client *gqlClient, endpoint string) *base.Finding {
	// Intentionally malformed query
	query := `{__schema{`
	r := client.sendQuery(ctx, endpoint, query, nil)

	if r.err != nil {
		return nil
	}

	lower := strings.ToLower(r.body)
	hasVerbose := strings.Contains(lower, "at ") && strings.Contains(lower, ".go:") || // Go stack trace
		strings.Contains(lower, "exception") ||
		strings.Contains(lower, "traceback") ||
		strings.Contains(lower, "stack trace") ||
		strings.Contains(lower, "internal server error") && strings.Contains(lower, "line")

	if hasVerbose {
		return &base.Finding{
			Type:       "GraphQL Verbose Error Information Disclosure",
			URL:        endpoint,
			Parameter:  "query",
			Payload:    query,
			Severity:   base.SeverityLow,
			Confidence: 0.82,
			Evidence: map[string]interface{}{
				"test":        "verbose_errors",
				"status_code": r.statusCode,
				"body_snippet": truncate(r.body, 500),
				"description": "GraphQL errors expose internal structure, file paths, or stack traces",
			},
			Method: "POST",
		}
	}
	return nil
}

// truncate truncates a string to at most n bytes for evidence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const defaultSystemPrompt = `You are a GraphQL security specialist. You test GraphQL APIs for:
1. Introspection enabled — full schema leakage
2. Field suggestion attacks — "Did you mean?" leaks valid field names
3. Batching abuse — array queries for DoS or rate-limit bypass
4. IDOR via object ID traversal in queries
5. __typename disclosure without authentication
6. Verbose errors revealing internal structure
7. Alias-based rate-limit bypass
8. Nested query depth attacks (DoS)

Severity: HIGH for IDOR/auth bypass, MEDIUM for introspection/batching/depth, LOW for info disclosure.`
