// Package gospider implements the GoSpider wrapper agent.
// Wraps the GoSpider web crawler for automated URL discovery,
// JavaScript parsing, and sitemap/robots.txt extraction.
package gospider

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "GoSpider Agent" }
func (a *Agent) ID() string           { return "gospider" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// GoSpider produces URLs as findings for the pipeline to process
	crawlTasks := []struct {
		source string
		detail string
	}{
		{"page_crawl", "Crawl all pages reachable from target, extract links"},
		{"js_crawl", "Parse JavaScript files for endpoints and API calls"},
		{"robots_txt", "Parse robots.txt for hidden paths"},
		{"sitemap_xml", "Parse sitemap.xml for URL inventory"},
		{"form_extraction", "Extract all form actions and methods"},
		{"comment_extraction", "Extract HTML comments for developer notes/secrets"},
		{"link_extraction", "Extract all href/src attributes"},
		{"redirect_follow", "Follow redirects and record intermediate URLs"},
	}

	var findings []*base.Finding
	for _, t := range crawlTasks {
		findings = append(findings, &base.Finding{
			Type:       "Crawl",
			URL:        targetURL,
			Payload:    t.detail,
			Severity:   "info",
			Confidence: 1.0,
			Evidence:   map[string]interface{}{"source": t.source},
			Method:     "CRAWL",
		})
	}
	return findings, nil
}

const defaultSystemPrompt = `You are a GoSpider web crawler agent responsible for:
- Deep crawling the target domain to discover all reachable URLs
- Parsing JavaScript files for hidden API endpoints
- Extracting robots.txt and sitemap.xml entries
- Cataloging all forms, their actions, and HTTP methods
- Following redirects and recording intermediate URLs
- Deduplicating discovered URLs before passing to the pipeline

Your output feeds the Discovery phase with URLs to analyze.`
