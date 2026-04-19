// Package cors implements the CORS Misconfiguration specialist agent.
//
// Tests for origin reflection, null origin, and wildcard+credentials issues.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"crypto/tls"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for CORS misconfiguration detection.
type Agent struct {
	systemPrompt string
}

// New creates a new CORS specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "CORS Agent" }
func (a *Agent) ID() string           { return "cors" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// corsResult holds the CORS headers from a single probe.
type corsResult struct {
	statusCode    int
	allowOrigin   string
	allowCreds    string
	varyHeader    string
	exposeHeaders string
	err           error
}

// ProcessItem tests a target URL for CORS misconfigurations.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	client := newHTTPClient()
	var findings []*base.Finding

	// Test 1: Origin reflection — send evil.com as Origin
	evilOrigin := "https://evil.com"
	res1 := sendCORSProbe(ctx, client, targetURL, evilOrigin)
	if res1.err == nil {
		conf, evidence := evaluateReflection(evilOrigin, res1)
		if conf > 0 {
			findings = append(findings, &base.Finding{
				Type:       "CORS Misconfiguration",
				URL:        targetURL,
				Parameter:  "Origin",
				Payload:    evilOrigin,
				Severity:   corsSeverity(conf),
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})
		}
	}

	// Test 2: Null origin
	res2 := sendCORSProbe(ctx, client, targetURL, "null")
	if res2.err == nil {
		conf, evidence := evaluateNull(res2)
		if conf > 0 {
			findings = append(findings, &base.Finding{
				Type:       "CORS Misconfiguration",
				URL:        targetURL,
				Parameter:  "Origin",
				Payload:    "null",
				Severity:   corsSeverity(conf),
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})
		}
	}

	// Test 3: Wildcard with credentials — check baseline (no Origin) response
	res3 := sendCORSProbe(ctx, client, targetURL, "")
	if res3.err == nil {
		conf, evidence := evaluateWildcardCredentials(res3)
		if conf > 0 {
			findings = append(findings, &base.Finding{
				Type:       "CORS Misconfiguration",
				URL:        targetURL,
				Parameter:  "Access-Control-Allow-Origin",
				Payload:    "wildcard+credentials",
				Severity:   corsSeverity(conf),
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})
		}
	}

	// Test 4: Subdomain takeover via crafted subdomain origin
	u, err := url.Parse(targetURL)
	if err == nil {
		subOrigin := "https://notevil." + u.Hostname()
		res4 := sendCORSProbe(ctx, client, targetURL, subOrigin)
		if res4.err == nil {
			conf, evidence := evaluateReflection(subOrigin, res4)
			if conf > 0 {
				evidence["subdomain_origin"] = true
				findings = append(findings, &base.Finding{
					Type:       "CORS Misconfiguration",
					URL:        targetURL,
					Parameter:  "Origin",
					Payload:    subOrigin,
					Severity:   corsSeverity(conf),
					Confidence: conf,
					Evidence:   evidence,
					Method:     "GET",
				})
			}
		}
	}

	return findings, nil
}

// sendCORSProbe sends a GET request with the given Origin header.
// An empty origin skips the Origin header (tests default CORS response).
func sendCORSProbe(ctx context.Context, client *http.Client, targetURL, origin string) corsResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return corsResult{err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	resp, err := client.Do(req)
	if err != nil {
		return corsResult{err: err}
	}
	defer resp.Body.Close()

	return corsResult{
		statusCode:    resp.StatusCode,
		allowOrigin:   resp.Header.Get("Access-Control-Allow-Origin"),
		allowCreds:    resp.Header.Get("Access-Control-Allow-Credentials"),
		varyHeader:    resp.Header.Get("Vary"),
		exposeHeaders: resp.Header.Get("Access-Control-Expose-Headers"),
	}
}

// evaluateReflection checks if the sent origin is reflected in the ACAO header.
func evaluateReflection(origin string, res corsResult) (float64, map[string]interface{}) {
	if res.allowOrigin != origin {
		return 0, nil
	}

	hasCreds := strings.EqualFold(res.allowCreds, "true")
	evidence := map[string]interface{}{
		"acao":        res.allowOrigin,
		"acac":        res.allowCreds,
		"vary":        res.varyHeader,
		"status_code": res.statusCode,
		"test":        "origin_reflection",
	}

	if hasCreds {
		// Reflected origin + credentials = highest risk
		return 0.9, evidence
	}
	return 0.7, evidence
}

// evaluateNull checks for null origin acceptance with credentials.
func evaluateNull(res corsResult) (float64, map[string]interface{}) {
	if res.allowOrigin != "null" {
		return 0, nil
	}

	evidence := map[string]interface{}{
		"acao":        res.allowOrigin,
		"acac":        res.allowCreds,
		"status_code": res.statusCode,
		"test":        "null_origin",
	}
	return 0.8, evidence
}

// evaluateWildcardCredentials checks if wildcard ACAO is combined with Allow-Credentials.
func evaluateWildcardCredentials(res corsResult) (float64, map[string]interface{}) {
	if res.allowOrigin != "*" {
		return 0, nil
	}
	if !strings.EqualFold(res.allowCreds, "true") {
		return 0, nil
	}

	evidence := map[string]interface{}{
		"acao":        res.allowOrigin,
		"acac":        res.allowCreds,
		"status_code": res.statusCode,
		"test":        "wildcard_with_credentials",
	}
	return 0.9, evidence
}

func corsSeverity(conf float64) string {
	if conf >= 0.85 {
		return "high"
	}
	return "medium"
}

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

const defaultSystemPrompt = `You are a CORS misconfiguration specialist. You detect overly permissive
cross-origin resource sharing policies that allow attackers to read authenticated responses.

Tests:
1. Origin reflection: does the server echo back any Origin in Access-Control-Allow-Origin?
2. Null origin: does the server accept Origin: null (sandboxed iframes)?
3. Wildcard + credentials: illegal combination that browsers block but misconfigured servers emit
4. Subdomain hijacking: does a forged subdomain origin get reflected?

Severity: HIGH when credentials are exposed, MEDIUM for unauthenticated reflection.`
