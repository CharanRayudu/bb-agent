package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// Skeptic is an agent that audits findings to ensure high precision
type Skeptic struct {
	llmProvider llm.Provider
}

// NewSkeptic creates a new finding validator
func NewSkeptic(provider llm.Provider) *Skeptic {
	return &Skeptic{llmProvider: provider}
}

// AuditResult represents the skeptic's verdict
type AuditResult struct {
	IsFalsePositive bool   `json:"is_false_positive"`
	Confidence      int    `json:"confidence"` // 1-100
	Reasoning       string `json:"reasoning"`
	SuggestedFix    string `json:"suggested_fix,omitempty"`
}

// Audit reviews a finding and its evidence
func (s *Skeptic) Audit(ctx context.Context, finding *Finding) (*AuditResult, error) {
	evidenceJSON, _ := json.Marshal(finding.Evidence)

	systemPrompt := `You are the "Skeptic" agent for a professional penetration testing system.
Your goal is to BE CRITICAL. Your objective is to find FALSE POSITIVES.
You will be given a finding and the raw evidence collected by another agent.

Analyze if:
1. The tool output really confirms the vulnerability (e.g., did "403 Forbidden" get confused for a successful injection?).
2. The payload actually executed meaningfully (e.g., for XSS, did the script run, or was it just reflected as text?).
3. The impact is real.

Output your verdict as JSON:
{
  "is_false_positive": bool,
  "confidence": int (0-100),
  "reasoning": "detailed explanation",
  "suggested_fix": "how to improve the payload or verification"
}`

	userPrompt := fmt.Sprintf("FINDING TYPE: %s\nURL: %s\nEVIDENCE:\n%s",
		finding.Type, finding.URL, string(evidenceJSON))

	resp, err := s.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	})

	if err != nil {
		return nil, err
	}

	var result AuditResult
	// Strip markdown markers if LLM included them
	cleanContent := strings.TrimSpace(resp.Content)
	if strings.HasPrefix(cleanContent, "```json") {
		cleanContent = strings.TrimPrefix(cleanContent, "```json")
		cleanContent = strings.TrimSuffix(cleanContent, "```")
	}

	if err := json.Unmarshal([]byte(cleanContent), &result); err != nil {
		return nil, fmt.Errorf("failed to parse skeptic response: %v", err)
	}

	return &result, nil
}
