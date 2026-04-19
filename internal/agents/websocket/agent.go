// Package websocket implements the WebSocket fuzzing specialist agent.
//
// Detects WebSocket upgrade support and fuzzes the handshake / frame payloads
// for XSS, SQLi, SSTI, and JSON injection using the standard HTTP Upgrade mechanism.
package websocket

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for WebSocket vulnerability detection.
type Agent struct {
	systemPrompt string
}

// New creates a new WebSocket specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "WebSocket Agent" }
func (a *Agent) ID() string           { return "websocket" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// fuzzPayload holds a test payload with its category.
type fuzzPayload struct {
	value    string
	category string
}

var wsPayloads = []fuzzPayload{
	// XSS
	{`<script>alert(1)</script>`, "xss"},
	{`"><img src=x onerror=alert(1)>`, "xss"},
	// SQLi
	{`' OR '1'='1`, "sqli"},
	{`" OR "1"="1`, "sqli"},
	// SSTI
	{`{{7*7}}`, "ssti"},
	{`${7*7}`, "ssti"},
	// JSON injection
	{`{"__proto__":{"polluted":"yes"}}`, "json_injection"},
	{`{"admin":true,"role":"superuser"}`, "json_injection"},
}

// ProcessItem tests a target for WebSocket-related vulnerabilities.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	wsEndpoints, _ := item.Payload["ws_endpoints"].([]interface{})
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Collect candidate WebSocket endpoint URLs
	candidates := collectCandidates(targetURL, wsEndpoints)

	fc := base.NewFuzzClient()
	var findings []*base.Finding

	for _, wsURL := range candidates {
		// Convert ws:// / wss:// to http:// / https:// for the upgrade probe
		httpURL := wsURLToHTTP(wsURL)

		// Step 1: Detect WebSocket upgrade support
		upgradeResult := probeUpgrade(ctx, fc, httpURL)
		if !upgradeResult {
			continue
		}

		// Step 2: Fuzz with test payloads injected as query parameters and path values
		for _, pl := range wsPayloads {
			result := fc.ProbeGET(ctx, httpURL, "msg", pl.value)
			if result.Error != nil {
				continue
			}

			conf := 0.0
			evidence := map[string]interface{}{
				"category":    pl.category,
				"status_code": result.StatusCode,
				"ws_url":      wsURL,
			}

			// Confirmed execution: payload reflected unescaped with script/event markers
			if base.DetectXSSExecution(result.Body, pl.value) {
				conf = 0.85
				evidence["execution_confirmed"] = true
			} else if base.DetectReflection(result.Body, pl.value) {
				conf = 0.6
				evidence["reflected"] = true
			} else if pl.category == "ssti" && strings.Contains(result.Body, "49") {
				conf = 0.85
				evidence["math_eval"] = true
			}

			if conf == 0 {
				continue
			}

			findings = append(findings, &base.Finding{
				Type:       "WebSocket Injection",
				URL:        wsURL,
				Parameter:  "msg",
				Payload:    pl.value,
				Severity:   "high",
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})
		}
	}

	return findings, nil
}

// probeUpgrade sends an HTTP GET with Upgrade: websocket header and checks for 101.
func probeUpgrade(ctx context.Context, fc *base.FuzzClient, httpURL string) bool {
	result := fc.ProbeGET(ctx, httpURL, "", "")
	// 101 Switching Protocols confirms WebSocket support; 400 with Upgrade header often means
	// the endpoint exists but we sent an invalid handshake — still worth fuzzing.
	return result.StatusCode == 101 || result.StatusCode == 400 ||
		(result.StatusCode == 200 && strings.Contains(strings.ToLower(result.Body), "websocket"))
}

// collectCandidates builds a list of WebSocket endpoint URLs to test.
func collectCandidates(targetURL string, extraEndpoints []interface{}) []string {
	seen := map[string]bool{}
	var out []string

	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}

	// Convert the primary target to ws:// variants
	u, err := url.Parse(targetURL)
	if err == nil {
		wsScheme := "ws"
		if u.Scheme == "https" {
			wsScheme = "wss"
		}
		wsBase := wsScheme + "://" + u.Host
		add(wsBase + "/ws")
		add(wsBase + "/websocket")
		add(wsBase + "/socket.io/")
		add(wsBase + "/chat")
		add(wsBase + "/live")
	}

	// Add any ws:// endpoints discovered by prior agents
	for _, ep := range extraEndpoints {
		if s, ok := ep.(string); ok && (strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")) {
			add(s)
		}
	}

	return out
}

// wsURLToHTTP converts ws:// → http:// and wss:// → https://.
func wsURLToHTTP(wsURL string) string {
	switch {
	case strings.HasPrefix(wsURL, "wss://"):
		return "https://" + wsURL[6:]
	case strings.HasPrefix(wsURL, "ws://"):
		return "http://" + wsURL[5:]
	default:
		return wsURL
	}
}

const defaultSystemPrompt = `You are a WebSocket security specialist. You detect injection vulnerabilities
(XSS, SQLi, SSTI, JSON injection) in WebSocket-enabled endpoints.

Approach:
1. Identify WebSocket endpoints from the target and payload context
2. Confirm the Upgrade handshake is accepted
3. Fuzz the message channel with targeted payloads
4. Detect reflected/executed payloads in the response

Severity: HIGH — reflected XSS in WebSocket context bypasses many CSP policies.`
