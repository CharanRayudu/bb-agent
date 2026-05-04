// Package ticketing provides integrations for creating issue tracker tickets
// from Mirage findings — Jira, GitHub Issues, and Linear.
package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Finding is the minimal finding shape needed to create a ticket.
type Finding struct {
	ID           string
	Type         string
	URL          string
	Severity     string
	Confidence   float64
	Title        string
	Description  string
	Remediation  string
	FlowID       string
	Evidence     map[string]interface{}
}

// TicketResult holds the result of creating a ticket.
type TicketResult struct {
	Provider  string
	TicketID  string
	TicketURL string
	Error     error
}

// JiraConfig holds credentials for Jira Cloud REST API v3.
type JiraConfig struct {
	BaseURL   string // e.g. https://yourorg.atlassian.net
	Email     string // Jira account email
	APIToken  string // Jira API token
	Project   string // Project key e.g. "SEC"
	IssueType string // e.g. "Bug" or "Security Vulnerability"
}

// GitHubConfig holds credentials for GitHub Issues API.
type GitHubConfig struct {
	Token  string // Personal access token or GitHub App token
	Owner  string // Repo owner e.g. "myorg"
	Repo   string // Repo name e.g. "security-findings"
}

// LinearConfig holds credentials for Linear GraphQL API.
type LinearConfig struct {
	APIKey    string // Linear API key
	TeamID    string // Linear team ID
	ProjectID string // Optional project ID
}

// slugSeverity maps severity to Jira priority name.
func jiraPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Lowest"
	}
}

// severityLabel maps severity to a GitHub label.
func githubLabel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "severity: critical"
	case "high":
		return "severity: high"
	case "medium":
		return "severity: medium"
	case "low":
		return "severity: low"
	default:
		return "severity: info"
	}
}

// buildGitHubBody formats a finding into GitHub Markdown.
func buildGitHubBody(f *Finding) string {
	var sb strings.Builder
	sb.WriteString("## Finding Summary\n\n")
	sb.WriteString("| Field | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| **Type** | `%s` |\n", f.Type))
	sb.WriteString(fmt.Sprintf("| **URL** | `%s` |\n", f.URL))
	sb.WriteString(fmt.Sprintf("| **Severity** | **%s** |\n", strings.ToUpper(f.Severity)))
	sb.WriteString(fmt.Sprintf("| **Confidence** | %.0f%% |\n", f.Confidence*100))
	sb.WriteString(fmt.Sprintf("| **Flow ID** | `%s` |\n\n", f.FlowID))

	if f.Description != "" {
		sb.WriteString("## Description\n\n")
		sb.WriteString(f.Description + "\n\n")
	}

	if f.Remediation != "" {
		sb.WriteString("## Remediation\n\n")
		sb.WriteString(f.Remediation + "\n\n")
	}

	if len(f.Evidence) > 0 {
		sb.WriteString("## Evidence\n\n```json\n")
		if b, err := json.MarshalIndent(f.Evidence, "", "  "); err == nil {
			sb.WriteString(string(b))
		}
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString("---\n*Created by [Mirage](https://github.com/bb-agent/mirage) Autonomous Pentest Platform*\n")
	return sb.String()
}

func findingTitle(f *Finding) string {
	if f.Title != "" {
		return f.Title
	}
	sev := strings.ToUpper(f.Severity)
	u := f.URL
	if len(u) > 60 {
		u = u[:57] + "..."
	}
	return fmt.Sprintf("[%s] %s — %s", sev, f.Type, u)
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func doRequest(ctx context.Context, client *http.Client, method, url string, body []byte, headers map[string]string) ([]byte, int, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return respBody, resp.StatusCode, err
}
