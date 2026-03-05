// Package assetdiscovery implements the Asset Discovery agent.
// Responsible for subdomain enumeration, JS file analysis,
// endpoint extraction, and technology fingerprinting.
package assetdiscovery

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Asset Discovery Agent" }
func (a *Agent) ID() string           { return "assetdiscovery" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Asset discovery produces leads, not findings directly.
	// Each discovered asset becomes a new work item for the pipeline.
	tasks := []struct {
		task   string
		detail string
	}{
		{"subdomain_enum", "Enumerate subdomains via DNS brute-force and certificate transparency"},
		{"js_analysis", "Extract endpoints, API keys, and secrets from JavaScript files"},
		{"endpoint_discovery", "Crawl and brute-force common API/admin endpoint paths"},
		{"tech_fingerprint", "Identify web server, framework, CMS, and library versions"},
		{"port_scan", "Check for exposed non-standard ports and services"},
		{"wayback_urls", "Retrieve historical URLs from the Wayback Machine"},
		{"robots_sitemap", "Parse robots.txt and sitemap.xml for hidden paths"},
		{"dns_records", "Enumerate DNS records (A, AAAA, CNAME, MX, TXT, NS)"},
	}

	var findings []*base.Finding
	for _, t := range tasks {
		findings = append(findings, &base.Finding{
			Type:       "Asset Discovery",
			URL:        targetURL,
			Payload:    t.detail,
			Severity:   "info",
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"task": t.task},
			Method:     "RECON",
		})
	}
	return findings, nil
}

const defaultSystemPrompt = `You are an expert Asset Discovery / Reconnaissance specialist:
- Subdomain enumeration (DNS brute-force, cert transparency, wayback)
- JavaScript static analysis (endpoint extraction, API key leaks)
- Technology fingerprinting (Wappalyzer-style header/response analysis)
- Endpoint brute-forcing (robots.txt, sitemap.xml, common paths)
- Port scanning and service identification

Your goal: Map the complete attack surface before exploitation begins.`
