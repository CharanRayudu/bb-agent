package remediation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// JiraConfig holds credentials for Jira Cloud.
type JiraConfig struct {
	BaseURL  string // e.g. https://your-org.atlassian.net
	Email    string
	APIToken string
	Project  string // project key, e.g. SEC
}

// JiraTicket holds the created issue reference.
type JiraTicket struct {
	Key string `json:"key"` // e.g. SEC-123
	URL string `json:"url"`
}

// CreateJiraIssue creates a Jira issue from a remediation item.
func CreateJiraIssue(ctx context.Context, cfg JiraConfig, it *Item) (*JiraTicket, error) {
	if cfg.BaseURL == "" || cfg.Email == "" || cfg.APIToken == "" || cfg.Project == "" {
		return nil, fmt.Errorf("incomplete Jira configuration")
	}

	priority := jiraPriority(it.Severity)

	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":   map[string]string{"key": cfg.Project},
			"summary":   fmt.Sprintf("[Security] %s — %s", it.Severity, it.Title),
			"issuetype": map[string]string{"name": "Bug"},
			"priority":  map[string]string{"name": priority},
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": []map[string]interface{}{
					{
						"type": "paragraph",
						"content": []map[string]interface{}{
							{"type": "text", "text": fmt.Sprintf("Severity: %s\nTarget: %s\nFinding Type: %s\n\n%s",
								strings.ToUpper(it.Severity), it.Target, it.FindingType, it.Description)},
						},
					},
				},
			},
			"labels": []string{"security", "mirage", it.Severity},
		},
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.BaseURL+"/rest/api/3/issue", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	creds := base64.StdEncoding.EncodeToString([]byte(cfg.Email + ":" + cfg.APIToken))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira request failed: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jira returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Key string `json:"key"`
		ID  string `json:"id"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("invalid Jira response: %w", err)
	}

	issueURL := cfg.BaseURL + "/browse/" + result.Key
	return &JiraTicket{Key: result.Key, URL: issueURL}, nil
}

func jiraPriority(severity string) string {
	switch severity {
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

// GitHubConfig holds credentials for GitHub Issues.
type GitHubConfig struct {
	Token string
	Owner string
	Repo  string
}

// GitHubIssue holds the created issue reference.
type GitHubIssue struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
}

// CreateGitHubIssue creates a GitHub issue from a remediation item.
func CreateGitHubIssue(ctx context.Context, cfg GitHubConfig, it *Item) (*GitHubIssue, error) {
	if cfg.Token == "" || cfg.Owner == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("incomplete GitHub configuration")
	}

	labels := []string{"security", it.Severity}
	body := map[string]interface{}{
		"title":  fmt.Sprintf("[Security/%s] %s", strings.ToUpper(it.Severity), it.Title),
		"body":   buildGitHubBody(it),
		"labels": labels,
	}

	payload, _ := json.Marshal(body)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", cfg.Owner, cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub request failed: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("invalid GitHub response: %w", err)
	}

	return &GitHubIssue{Number: result.Number, URL: result.HTMLURL}, nil
}

func buildGitHubBody(it *Item) string {
	var sb strings.Builder
	sb.WriteString("## Security Finding\n\n")
	sb.WriteString("| Field | Value |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **Severity** | `%s` |\n", strings.ToUpper(it.Severity)))
	sb.WriteString(fmt.Sprintf("| **Type** | %s |\n", it.FindingType))
	sb.WriteString(fmt.Sprintf("| **Target** | `%s` |\n", it.Target))
	if it.RiskScore > 0 {
		sb.WriteString(fmt.Sprintf("| **Risk Score** | %.1f |\n", it.RiskScore))
	}
	sb.WriteString("\n")
	if it.Description != "" {
		sb.WriteString("## Description\n\n")
		sb.WriteString(it.Description)
		sb.WriteString("\n\n")
	}
	sb.WriteString("## Remediation\n\nPlease address this finding and update the status in [Mirage](https://mirage.sec).\n\n")
	sb.WriteString(fmt.Sprintf("*Created by Mirage Autonomous Pentest · Finding ID: `%s`*\n", it.FindingID))
	return sb.String()
}
