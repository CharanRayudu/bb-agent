package agent

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// Reflector represents the post-execution validation agent.
// It analyzes completion criteria against execution logs to prevent
// hallucinations and false positives.
type Reflector struct {
	llmProvider llm.Provider
}

// NewReflector creates a new Reflector agent
func NewReflector(llmProvider llm.Provider) *Reflector {
	return &Reflector{
		llmProvider: llmProvider,
	}
}

// ValidateFinding asks the LLM to objectively verify if the execution log
// proves that the goal was achieved, and verifies the reported finding.
// Returns (isValid, feedback/veto_reason)
func (r *Reflector) ValidateFinding(ctx context.Context, systemPrompt string, executionLog []models.ChatMessage, reportedFinding string) (bool, string) {
	// 1. Build a compressed summary of what the agent actually did
	var logSummary strings.Builder
	for _, msg := range executionLog {
		if msg.Role == "tool" || msg.Role == "assistant" {
			logSummary.WriteString(fmt.Sprintf("[%s]: %s\n", msg.Role, truncate(msg.Content, 500)))
		}
	}

	// 2. Build the Reflector's prompt
	prompt := fmt.Sprintf(`You are a strict, skeptical Penetration Testing Auditor.
Your job is to review a specialist agent's reported finding and verify if it is ACTUALLY proven by the execution logs.
Agents sometimes hallucinate or assume success without proof.

AGENT'S ORIGINAL DIRECTIVE:
%s

EXECUTION LOG SUMMARY (What the agent actually did and saw):
%s

AGENT'S REPORTED FINDING:
%s

Analyze the execution log. Does the log contain concrete, undeniable proof that the finding is valid?
(e.g., if claiming SQLi, is there proof of database data extracted or a sleep() confirmed? If claiming XSS, is there proof the payload reflected in a dangerous context?)

Respond in EXACTLY this format:
VALID: [true/false]
REASON: [A concise 1-2 sentence explanation of why you accepted or vetoed the finding. If false, point out exactly what proof is missing so the agent can try again.]`, systemPrompt, logSummary.String(), reportedFinding)

	// 3. Ask the LLM to reflect (using a low temperature if supported, but here we just use the default completion)
	resp, err := r.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a rigid security auditor. You require hard proof."},
			{Role: "user", Content: prompt},
		},
	})

	if err != nil {
		log.Printf("[Reflector] Error calling LLM: %v", err)
		// Fallback: If reflector fails, we don't block the pipeline, we cautiously accept
		return true, "Reflector LLM failed, automatically accepting."
	}

	content := resp.Content
	
	valid := false
	if strings.Contains(strings.ToUpper(content), "VALID: TRUE") {
		valid = true
	}

	// Extract the reason
	reason := "No reason provided."
	parts := strings.SplitAfter(content, "REASON:")
	if len(parts) > 1 {
		reason = strings.TrimSpace(parts[1])
	}

	return valid, reason
}
