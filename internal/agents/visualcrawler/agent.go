// Package visualcrawler implements the Visual Crawler specialist agent.
// Uses the shared browser helper so browser failures degrade consistently.
package visualcrawler

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct {
	systemPrompt string
}

func New() *Agent {
	return &Agent{
		systemPrompt: defaultSystemPrompt,
	}
}

func (a *Agent) Name() string         { return "Visual Crawler" }
func (a *Agent) ID() string           { return "visualcrawler" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	fmt.Printf("[VisualCrawler] Starting headless crawl of %s\n", targetURL)

	results, err := base.RunCrawl(ctx, targetURL, base.DefaultBrowserOptions())
	if err != nil {
		if base.IsBrowserUnavailableError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("visual crawl failed: %w", err)
	}

	var findings []*base.Finding
	for _, link := range results.Links {
		if shouldKeepDiscoveredLink(targetURL, link) {
			findings = append(findings, &base.Finding{
				Type:       "URL Lead (Headless)",
				URL:        link,
				Severity:   "informational",
				Confidence: 1.0,
				Evidence: map[string]interface{}{
					"source":  "visualcrawler",
					"context": "headless browser discovery",
				},
			})
		}
	}

	return findings, nil
}

func shouldKeepDiscoveredLink(targetURL, discovered string) bool {
	if !strings.HasPrefix(discovered, "http://") && !strings.HasPrefix(discovered, "https://") {
		return false
	}

	targetParsed, err := url.Parse(targetURL)
	if err != nil || targetParsed.Hostname() == "" {
		return false
	}

	discoveredParsed, err := url.Parse(discovered)
	if err != nil || discoveredParsed.Hostname() == "" {
		return false
	}

	targetHost := strings.ToLower(targetParsed.Hostname())
	discoveredHost := strings.ToLower(discoveredParsed.Hostname())

	if discoveredHost == targetHost {
		return true
	}

	return strings.HasSuffix(discoveredHost, "."+targetHost)
}

const defaultSystemPrompt = `You are a Visual Crawler, a specialist in modern web application discovery.

Your job: use a headless browser to see what static analysis misses.

Key activities:
1. Navigation: wait for JavaScript frameworks to render.
2. Interaction: identify buttons, clickable elements, and hidden listeners.
3. Discovery: capture dynamically generated URLs and API endpoints.
4. Feature extraction: identify state management, postMessage events, and custom headers.

Rules:
- Focus on finding URL leads for exploitation agents.
- Identify complex SPA patterns such as hash routing and client-side auth tokens.
- Prioritize endpoints that look like administrative interfaces or sensitive functions.`
