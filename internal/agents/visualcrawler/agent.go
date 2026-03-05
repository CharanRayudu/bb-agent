// Package visualcrawler implements the Visual Crawler specialist agent.
// Uses a headless browser to find links, buttons, and API endpoints
// in modern Single Page Applications (React, Vue, etc.) that
// static crawlers (GoSpider) might miss.
package visualcrawler

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
	"github.com/chromedp/chromedp"
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

	fmt.Printf("[VisualCrawler] 📸 Starting headless crawl of %s\n", targetURL)

	// We use Chromedp directly for crawling (low-level access)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, chromedp.DefaultExecAllocatorOptions[:]...)
	defer cancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	links := []string{}
	inputs := []string{}

	err := chromedp.Run(browserCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3000), // Give SPA time to render
		chromedp.Evaluate(`
			(function() {
				let result = {links: [], inputs: []};
				// Find all anchors
				document.querySelectorAll('a').forEach(a => {
					if (a.href) result.links.push(a.href);
				});
				// Find all inputs, buttons, textareas
				document.querySelectorAll('input, button, textarea, select').forEach(i => {
					let name = i.name || i.id || i.placeholder || i.innerText;
					if (name) result.inputs.push(name);
				});
				// Future: Detect postMessage listeners and custom events
				return result;
			})()
		`, &struct {
			Links  []string `json:"links"`
			Inputs []string `json:"inputs"`
		}{Links: links, Inputs: inputs}),
	)

	if err != nil {
		return nil, fmt.Errorf("visual crawl failed: %w", err)
	}

	var findings []*base.Finding
	for _, link := range links {
		if strings.HasPrefix(link, "http") {
			findings = append(findings, &base.Finding{
				Type:       "URL Lead (Headless)",
				URL:        link,
				Payload:    "",
				Severity:   "informational",
				Confidence: 1.0,
				Evidence: map[string]interface{}{
					"source":  "visualcrawler",
					"context": "Headless browser discovery",
				},
			})
		}
	}

	return findings, nil
}

const defaultSystemPrompt = `You are a Visual Crawler — a specialist in modern web application discovery:

Your job: Use a headless browser to "see" what static analysis misses.

Key Activities:
1. NAVIGATION: Wait for JavaScript frameworks (React, Vue, Angular) to fully render.
2. INTERACTION: Identify buttons, clickable elements, and hidden listeners.
3. DISCOVERY: Capture dynamically generated URLs and API endpoints.
4. FEATURE EXTRACTION: Identify state management, postMessage events, and custom headers.

RULES:
- Focus on finding URL "Leads" for exploitation agents.
- Identify complex SPA patterns (e.g. #/routing, client-side auth tokens).
- Prioritize endpoints that look like administrative interfaces or sensitive functions.`
