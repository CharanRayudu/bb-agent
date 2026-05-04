package ticketing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// CreateJiraTicket creates a Jira issue from a finding using the Jira Cloud REST API v3.
func CreateJiraTicket(ctx context.Context, cfg JiraConfig, f *Finding) TicketResult {
	if cfg.BaseURL == "" || cfg.Email == "" || cfg.APIToken == "" || cfg.Project == "" {
		return TicketResult{Provider: "jira", Error: fmt.Errorf("jira config incomplete: baseURL, email, apiToken, and project are required")}
	}

	issueType := cfg.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	// Build the issue body using Atlassian Document Format (ADF)
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":   map[string]string{"key": cfg.Project},
			"summary":   findingTitle(f),
			"issuetype": map[string]string{"name": issueType},
			"priority":  map[string]string{"name": jiraPriority(f.Severity)},
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": buildADFContent(f),
			},
			"labels": buildJiraLabels(f),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return TicketResult{Provider: "jira", Error: err}
	}

	token := base64.StdEncoding.EncodeToString([]byte(cfg.Email + ":" + cfg.APIToken))
	url := strings.TrimRight(cfg.BaseURL, "/") + "/rest/api/3/issue"

	respBody, status, err := doRequest(ctx, newHTTPClient(), "POST", url, body, map[string]string{
		"Authorization": "Basic " + token,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
	})
	if err != nil {
		return TicketResult{Provider: "jira", Error: fmt.Errorf("jira request failed: %w", err)}
	}
	if status < 200 || status >= 300 {
		return TicketResult{Provider: "jira", Error: fmt.Errorf("jira returned HTTP %d: %s", status, string(respBody))}
	}

	var result struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return TicketResult{Provider: "jira", Error: fmt.Errorf("jira response parse error: %w", err)}
	}

	ticketURL := strings.TrimRight(cfg.BaseURL, "/") + "/browse/" + result.Key
	return TicketResult{
		Provider:  "jira",
		TicketID:  result.Key,
		TicketURL: ticketURL,
	}
}

// buildADFContent builds Atlassian Document Format content nodes for the issue description.
func buildADFContent(f *Finding) []interface{} {
	heading := func(text string, level int) map[string]interface{} {
		return map[string]interface{}{
			"type": "heading",
			"attrs": map[string]int{"level": level},
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		}
	}
	paragraph := func(text string) map[string]interface{} {
		return map[string]interface{}{
			"type":    "paragraph",
			"content": []map[string]interface{}{{"type": "text", "text": text}},
		}
	}
	codeBlock := func(code string) map[string]interface{} {
		return map[string]interface{}{
			"type":  "codeBlock",
			"attrs": map[string]string{"language": "json"},
			"content": []map[string]interface{}{
				{"type": "text", "text": code},
			},
		}
	}

	content := []interface{}{
		heading("Finding Details", 2),
		paragraph(fmt.Sprintf("Type: %s | URL: %s | Severity: %s | Confidence: %.0f%% | Flow: %s",
			f.Type, f.URL, strings.ToUpper(f.Severity), f.Confidence*100, f.FlowID)),
	}

	if f.Description != "" {
		content = append(content, heading("Description", 3), paragraph(f.Description))
	}

	if f.Remediation != "" {
		content = append(content, heading("Remediation", 3), paragraph(f.Remediation))
	}

	if len(f.Evidence) > 0 {
		if b, err := json.MarshalIndent(f.Evidence, "", "  "); err == nil {
			content = append(content, heading("Evidence", 3), codeBlock(string(b)))
		}
	}

	content = append(content, paragraph("Created by Mirage Autonomous Pentest Platform"))
	return content
}

func buildJiraLabels(f *Finding) []string {
	labels := []string{"security", "mirage", f.Severity}
	// Normalize finding type to a label (replace _ with -, lowercase)
	if f.Type != "" {
		labels = append(labels, strings.ToLower(strings.ReplaceAll(f.Type, "_", "-")))
	}
	return labels
}
