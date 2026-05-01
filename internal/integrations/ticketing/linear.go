package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Linear priority IDs: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low
func linearPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1 // Urgent
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 0
	}
}

// CreateLinearIssue creates a Linear issue from a finding using the Linear GraphQL API.
func CreateLinearIssue(ctx context.Context, cfg LinearConfig, f *Finding) TicketResult {
	if cfg.APIKey == "" || cfg.TeamID == "" {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear config incomplete: apiKey and teamID are required")}
	}

	title := findingTitle(f)
	description := buildLinearDescription(f)
	priority := linearPriority(f.Severity)

	variables := map[string]interface{}{
		"title":       title,
		"teamId":      cfg.TeamID,
		"description": description,
		"priority":    priority,
	}
	if cfg.ProjectID != "" {
		variables["projectId"] = cfg.ProjectID
	}

	query := `
mutation CreateIssue($title: String!, $teamId: String!, $description: String, $priority: Int, $projectId: String) {
  issueCreate(input: {
    title: $title
    teamId: $teamId
    description: $description
    priority: $priority
    projectId: $projectId
  }) {
    success
    issue {
      id
      identifier
      url
    }
  }
}`

	payload, err := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return TicketResult{Provider: "linear", Error: err}
	}

	respBody, status, err := doRequest(ctx, newHTTPClient(), "POST", "https://api.linear.app/graphql", payload, map[string]string{
		"Authorization": cfg.APIKey,
		"Content-Type":  "application/json",
	})
	if err != nil {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear request failed: %w", err)}
	}
	if status < 200 || status >= 300 {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear returned HTTP %d: %s", status, string(respBody))}
	}

	var result struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
				Issue   struct {
					ID         string `json:"id"`
					Identifier string `json:"identifier"`
					URL        string `json:"url"`
				} `json:"issue"`
			} `json:"issueCreate"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear response parse error: %w", err)}
	}
	if len(result.Errors) > 0 {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear GraphQL error: %s", result.Errors[0].Message)}
	}
	if !result.Data.IssueCreate.Success {
		return TicketResult{Provider: "linear", Error: fmt.Errorf("linear issue creation failed")}
	}

	issue := result.Data.IssueCreate.Issue
	return TicketResult{
		Provider:  "linear",
		TicketID:  issue.Identifier,
		TicketURL: issue.URL,
	}
}

func buildLinearDescription(f *Finding) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Type:** `%s`  \n", f.Type))
	sb.WriteString(fmt.Sprintf("**URL:** `%s`  \n", f.URL))
	sb.WriteString(fmt.Sprintf("**Severity:** **%s**  \n", strings.ToUpper(f.Severity)))
	sb.WriteString(fmt.Sprintf("**Confidence:** %.0f%%  \n", f.Confidence*100))
	sb.WriteString(fmt.Sprintf("**Flow ID:** `%s`\n\n", f.FlowID))

	if f.Description != "" {
		sb.WriteString("### Description\n\n" + f.Description + "\n\n")
	}
	if f.Remediation != "" {
		sb.WriteString("### Remediation\n\n" + f.Remediation + "\n\n")
	}
	if len(f.Evidence) > 0 {
		if b, err := json.MarshalIndent(f.Evidence, "", "  "); err == nil {
			sb.WriteString("### Evidence\n\n```json\n" + string(b) + "\n```\n\n")
		}
	}
	sb.WriteString("---\n*Created by Mirage Autonomous Pentest Platform*\n")
	return sb.String()
}
