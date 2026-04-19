// Package cachepoisoning implements the Cache Poisoning specialist agent.
//
// Tests injection of unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.)
// and verifies whether the injected value is reflected in the response body or
// cached for subsequent requests.
package cachepoisoning

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for Cache Poisoning detection.
type Agent struct {
	systemPrompt string
}

// New creates a new Cache Poisoning specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Cache Poisoning Agent" }
func (a *Agent) ID() string           { return "cachepoisoning" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// poisonProbe defines a header injection test case.
type poisonProbe struct {
	headerName  string
	headerValue string
	label       string
}

// cacheBuster generates a unique query suffix to prevent hitting a warm cache.
func cacheBuster() string {
	return fmt.Sprintf("cb%d", time.Now().UnixNano()%1_000_000)
}

// ProcessItem tests a target URL for cache poisoning via unkeyed header injection.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	client := newHTTPClient()

	// Poison marker: a value unlikely to appear in any legitimate response.
	marker := "CACHEPOISONTEST"

	probes := []poisonProbe{
		{
			headerName:  "X-Forwarded-Host",
			headerValue: marker + ".evil.com",
			label:       "X-Forwarded-Host injection",
		},
		{
			headerName:  "X-Original-URL",
			headerValue: "/" + marker,
			label:       "X-Original-URL injection",
		},
		{
			headerName:  "X-Rewrite-URL",
			headerValue: "/" + marker,
			label:       "X-Rewrite-URL injection",
		},
		{
			headerName:  "X-Host",
			headerValue: marker + ".evil.com",
			label:       "X-Host injection",
		},
		{
			headerName:  "X-Forwarded-Server",
			headerValue: marker + ".evil.com",
			label:       "X-Forwarded-Server injection",
		},
		{
			headerName:  "X-HTTP-Host-Override",
			headerValue: marker + ".evil.com",
			label:       "X-HTTP-Host-Override injection",
		},
	}

	var findings []*base.Finding

	for _, probe := range probes {
		bust := cacheBuster()
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		probeURL := targetURL + sep + "_cb=" + bust

		result := sendPoisonProbe(ctx, client, probeURL, probe.headerName, probe.headerValue)
		if result.err != nil {
			continue
		}

		reflected := strings.Contains(result.body, marker)
		if !reflected {
			// Also check response headers for the marker (e.g. Location redirect)
			reflected = strings.Contains(result.headerDump, marker)
		}

		if !reflected {
			continue
		}

		findings = append(findings, &base.Finding{
			Type:       "Cache Poisoning",
			URL:        targetURL,
			Parameter:  probe.headerName,
			Payload:    probe.headerValue,
			Severity:   "high",
			Confidence: 0.8,
			Evidence: map[string]interface{}{
				"label":       probe.label,
				"marker":      marker,
				"reflected":   true,
				"status_code": result.statusCode,
				"cache_buster": bust,
			},
			Method: "GET",
		})
	}

	return findings, nil
}

type probeResult struct {
	statusCode int
	body       string
	headerDump string
	err        error
}

// sendPoisonProbe sends a GET with a poisoning header and returns the response.
func sendPoisonProbe(ctx context.Context, client *http.Client, targetURL, headerName, headerValue string) probeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return probeResult{err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	req.Header.Set(headerName, headerValue)
	// Prevent our own request from serving a cached poison
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{err: err}
	}
	defer resp.Body.Close()

	buf := make([]byte, 512*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Dump relevant response headers to a single string for reflection check
	var headerParts []string
	for k, vs := range resp.Header {
		for _, v := range vs {
			headerParts = append(headerParts, k+": "+v)
		}
	}
	headerDump := strings.Join(headerParts, "\n")

	return probeResult{
		statusCode: resp.StatusCode,
		body:       body,
		headerDump: headerDump,
	}
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

const defaultSystemPrompt = `You are a Cache Poisoning specialist. You exploit unkeyed HTTP request headers
that CDNs/reverse proxies forward to the origin but do not include in the cache key.

Key headers to test:
- X-Forwarded-Host: rewrites the Host seen by the back-end (most impactful)
- X-Original-URL / X-Rewrite-URL: path override
- X-Forwarded-Server / X-HTTP-Host-Override

Methodology:
1. Add a cache buster to avoid hitting a stale cache
2. Inject a recognizable marker in each header
3. Check if the marker appears in the response body or Location header
4. If reflected, the endpoint is vulnerable to Web Cache Poisoning

Confidence: 0.8 when marker is reflected in body/headers.`
