package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CreateGitHubIssue creates a GitHub Issue from a finding using the GitHub REST API.
func CreateGitHubIssue(ctx context.Context, cfg GitHubConfig, f *Finding) TicketResult {
	if cfg.Token == "" || cfg.Owner == "" || cfg.Repo == "" {
		return TicketResult{Provider: "github", Error: fmt.Errorf("github config incomplete: token, owner, and repo are required")}
	}

	// Ensure the severity label exists (best-effort, ignore errors)
	ensureGitHubLabel(ctx, cfg, githubLabel(f.Severity), labelColor(f.Severity))

	labels := []string{"security", "mirage", githubLabel(f.Severity)}
	if f.Type != "" {
		labels = append(labels, strings.ToLower(strings.ReplaceAll(f.Type, "_", "-")))
	}

	payload := map[string]interface{}{
		"title":  findingTitle(f),
		"body":   buildGitHubBody(f),
		"labels": labels,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return TicketResult{Provider: "github", Error: err}
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", cfg.Owner, cfg.Repo)
	respBody, status, err := doRequest(ctx, newHTTPClient(), "POST", url, body, map[string]string{
		"Authorization": "Bearer " + cfg.Token,
		"Content-Type":  "application/json",
		"Accept":        "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	})
	if err != nil {
		return TicketResult{Provider: "github", Error: fmt.Errorf("github request failed: %w", err)}
	}
	if status < 200 || status >= 300 {
		return TicketResult{Provider: "github", Error: fmt.Errorf("github returned HTTP %d: %s", status, string(respBody))}
	}

	var result struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return TicketResult{Provider: "github", Error: fmt.Errorf("github response parse error: %w", err)}
	}

	return TicketResult{
		Provider:  "github",
		TicketID:  fmt.Sprintf("#%d", result.Number),
		TicketURL: result.HTMLURL,
	}
}

// ensureGitHubLabel creates a label if it doesn't already exist.
func ensureGitHubLabel(ctx context.Context, cfg GitHubConfig, name, color string) {
	payload, _ := json.Marshal(map[string]string{"name": name, "color": color})
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/labels", cfg.Owner, cfg.Repo)
	doRequest(ctx, newHTTPClient(), "POST", url, payload, map[string]string{ //nolint:errcheck
		"Authorization":        "Bearer " + cfg.Token,
		"Content-Type":         "application/json",
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	})
}

func labelColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "b60205"
	case "high":
		return "e4e669"
	case "medium":
		return "fbca04"
	case "low":
		return "0075ca"
	default:
		return "cccccc"
	}
}
