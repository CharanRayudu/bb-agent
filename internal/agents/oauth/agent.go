// Package oauth implements the OAuth/OIDC Misconfiguration specialist agent.
//
// Detects open redirect in redirect_uri, missing/static state parameter,
// and token leakage issues.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"crypto/tls"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for OAuth/OIDC detection.
type Agent struct {
	systemPrompt string
}

// New creates a new OAuth/OIDC specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "OAuth/OIDC Agent" }
func (a *Agent) ID() string           { return "oauth" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// oauthEndpoint describes a detected OAuth endpoint.
type oauthEndpoint struct {
	url      string
	endpType string // "authorize", "token", "discovery"
}

// ProcessItem scans a target for OAuth/OIDC misconfigurations.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := newHTTPClient()
	fc := base.NewFuzzClient()

	// Step 1: Detect OAuth endpoints
	endpoints := discoverEndpoints(ctx, fc, u)
	if len(endpoints) == 0 {
		// No OAuth endpoints detected
		return nil, nil
	}

	var findings []*base.Finding

	for _, ep := range endpoints {
		if ep.endpType == "authorize" {
			// Test 1: open redirect in redirect_uri
			f := testOpenRedirect(ctx, client, ep.url)
			findings = append(findings, f...)

			// Test 2: missing/static state parameter
			f2 := testStateMissing(ctx, client, ep.url)
			findings = append(findings, f2...)
		}

		if ep.endpType == "discovery" {
			// Test 3: token leakage hints in the discovery doc
			f3 := testDiscoveryLeakage(ctx, fc, ep.url)
			findings = append(findings, f3...)
		}
	}

	return findings, nil
}

// discoverEndpoints probes common OAuth paths and checks for 200/302/400 responses.
func discoverEndpoints(ctx context.Context, fc *base.FuzzClient, u *url.URL) []oauthEndpoint {
	base := u.Scheme + "://" + u.Host

	candidates := []struct {
		path     string
		endpType string
	}{
		{"/oauth/authorize", "authorize"},
		{"/oauth2/authorize", "authorize"},
		{"/authorize", "authorize"},
		{"/oauth/token", "token"},
		{"/oauth2/token", "token"},
		{"/token", "token"},
		{"/.well-known/openid-configuration", "discovery"},
		{"/.well-known/oauth-authorization-server", "discovery"},
	}

	var found []oauthEndpoint
	for _, c := range candidates {
		fullURL := base + c.path
		result := fc.ProbeGET(ctx, fullURL, "", "")
		if result.Error != nil {
			continue
		}
		// 200, 302, 400 all suggest the endpoint exists
		if result.StatusCode == 200 || result.StatusCode == 302 || result.StatusCode == 400 {
			found = append(found, oauthEndpoint{url: fullURL, endpType: c.endpType})
		}
	}

	// Also check if targetURL path looks like an OAuth endpoint
	path := strings.ToLower(u.Path)
	if strings.Contains(path, "/oauth") || strings.Contains(path, "/authorize") {
		found = append(found, oauthEndpoint{url: u.String(), endpType: "authorize"})
	}

	return found
}

// testOpenRedirect tries to bypass redirect_uri validation.
func testOpenRedirect(ctx context.Context, client *http.Client, authorizeURL string) []*base.Finding {
	var findings []*base.Finding

	// Common bypass patterns for redirect_uri
	bypasses := []struct {
		value string
		label string
	}{
		{"https://evil.com", "direct_evil"},
		{"https://evil.com/", "trailing_slash"},
		{"https://evil.com%2F@legit.com", "at_sign_bypass"},
		{"https://legit.com.evil.com", "subdomain_lookalike"},
		{"//evil.com", "protocol_relative"},
	}

	for _, bp := range bypasses {
		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", "test")
		params.Set("redirect_uri", bp.value)
		params.Set("state", "teststate123")

		probeURL := authorizeURL + "?" + params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// 302 to evil.com = confirmed redirect bypass
		if resp.StatusCode == 302 || resp.StatusCode == 301 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") {
				findings = append(findings, &base.Finding{
					Type:       "OAuth Open Redirect",
					URL:        authorizeURL,
					Parameter:  "redirect_uri",
					Payload:    bp.value,
					Severity:   "high",
					Confidence: 0.85,
					Evidence: map[string]interface{}{
						"bypass_label":  bp.label,
						"location":      loc,
						"status_code":   resp.StatusCode,
					},
					Method: "GET",
				})
				break // One confirmed finding is enough per endpoint
			}
		}
	}

	return findings
}

// testStateMissing checks if authorization requests succeed without a state parameter.
func testStateMissing(ctx context.Context, client *http.Client, authorizeURL string) []*base.Finding {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test")
	params.Set("redirect_uri", "https://example.com/callback")
	// Deliberately omit "state"

	probeURL := authorizeURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	// If server doesn't return 400 on missing state, it may be vulnerable to CSRF
	if resp.StatusCode != 400 && resp.StatusCode != 403 {
		return []*base.Finding{{
			Type:       "OAuth Missing State Parameter",
			URL:        authorizeURL,
			Parameter:  "state",
			Payload:    "(omitted)",
			Severity:   "medium",
			Confidence: 0.8,
			Evidence: map[string]interface{}{
				"status_code": resp.StatusCode,
				"description": "Authorization endpoint accepted request without state parameter (CSRF risk)",
			},
			Method: "GET",
		}}
	}
	return nil
}

// testDiscoveryLeakage checks the OIDC discovery document for risky configuration.
func testDiscoveryLeakage(ctx context.Context, fc *base.FuzzClient, discoveryURL string) []*base.Finding {
	result := fc.ProbeGET(ctx, discoveryURL, "", "")
	if result.Error != nil || result.StatusCode != 200 {
		return nil
	}

	body := strings.ToLower(result.Body)
	var findings []*base.Finding

	// Check for implicit flow enabled (token leakage via URL fragment)
	if strings.Contains(body, `"token"`) && strings.Contains(body, `response_types_supported`) {
		if strings.Contains(body, `"id_token"`) || strings.Contains(body, `"token id_token"`) {
			findings = append(findings, &base.Finding{
				Type:       "OAuth Implicit Flow Enabled",
				URL:        discoveryURL,
				Parameter:  "response_types_supported",
				Payload:    "id_token / token",
				Severity:   "medium",
				Confidence: 0.7,
				Evidence: map[string]interface{}{
					"description": "Implicit flow exposes tokens in URL fragment (referrer leakage risk)",
					"status_code": result.StatusCode,
				},
				Method: "GET",
			})
		}
	}

	return findings
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

const defaultSystemPrompt = `You are an OAuth/OIDC security specialist. You detect:
- Open redirect in redirect_uri parameter (attacker steals authorization codes)
- Missing/static state parameter (CSRF on authorization flow)
- Implicit flow enabled (tokens exposed in URL fragment → referrer leakage)
- Token leakage via discovery document misconfiguration

Severity: HIGH for redirect_uri bypass, MEDIUM for missing state/implicit flow.`
