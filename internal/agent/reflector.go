package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// FailureLevel classifies why an execution attempt failed.
type FailureLevel string

const (
	FailureNone FailureLevel = ""
	// L1: Tool failure -- retry with different parameters
	FailureL1Tool FailureLevel = "L1_TOOL_FAILURE"
	// L2: Approach failure -- pivot strategy entirely
	FailureL2Approach FailureLevel = "L2_APPROACH_FAILURE"
	// L3: Scope failure -- target is not vulnerable to this class
	FailureL3Scope FailureLevel = "L3_SCOPE_FAILURE"
	// L4: Systematic failure -- update knowledge base for future
	FailureL4Systematic FailureLevel = "L4_SYSTEMATIC_FAILURE"
)

// ReflectionResult captures the Reflector's analysis of an execution.
type ReflectionResult struct {
	IsValid       bool         `json:"is_valid"`
	FailureLevel  FailureLevel `json:"failure_level"`
	Reasoning     string       `json:"reasoning"`
	Feedback      string       `json:"feedback"`
	SuggestedNext string       `json:"suggested_next"`
	ShouldRetry   bool         `json:"should_retry"`
	Intelligence  string       `json:"intelligence"` // learnings for the knowledge base
	Confidence    float64      `json:"confidence"`
}

// Reflector audits execution results, performs L1-L4 failure analysis,
// generates attack intelligence, and determines goal achievement.
// It feeds learnings back to the Planner for strategy evolution.
type Reflector struct {
	llmProvider llm.Provider
}

// NewReflector creates a new Reflector agent.
func NewReflector(llmProvider llm.Provider) *Reflector {
	return &Reflector{
		llmProvider: llmProvider,
	}
}

// Reflect performs full analysis of an execution result.
// Returns a ReflectionResult with failure classification, feedback, and intelligence.
func (r *Reflector) Reflect(ctx context.Context, task string, result *ExecutionResult) (*ReflectionResult, error) {
	if result == nil {
		return &ReflectionResult{
			IsValid:      false,
			FailureLevel: FailureL1Tool,
			Reasoning:    "No execution result to reflect on",
			ShouldRetry:  true,
		}, nil
	}

	// Build the execution summary for the LLM
	var execSummary strings.Builder
	execSummary.WriteString(fmt.Sprintf("TASK: %s\n", task))
	execSummary.WriteString(fmt.Sprintf("SUCCESS: %v\n", result.Success))
	execSummary.WriteString(fmt.Sprintf("STEPS: %d\n", result.StepCount))
	execSummary.WriteString(fmt.Sprintf("TOOLS USED: %s\n", strings.Join(result.ToolsUsed, ", ")))
	execSummary.WriteString(fmt.Sprintf("CONFIDENCE: %.2f\n", result.Confidence))
	if result.Error != "" {
		execSummary.WriteString(fmt.Sprintf("ERROR: %s\n", result.Error))
	}
	execSummary.WriteString(fmt.Sprintf("DURATION: %s\n", result.Duration))

	// Include a compressed message log
	execSummary.WriteString("\nEXECUTION LOG (compressed):\n")
	for _, msg := range result.Messages {
		if msg.Role == "tool" || msg.Role == "assistant" {
			content := truncate(msg.Content, 300)
			if content != "" {
				execSummary.WriteString(fmt.Sprintf("[%s]: %s\n", msg.Role, content))
			}
		}
	}

	prompt := fmt.Sprintf(`You are the Reflector in a P-E-R (Planner-Executor-Reflector) autonomous pentest system.

Analyze the execution result below and classify the outcome.

%s

FAILURE CLASSIFICATION:
- L1_TOOL_FAILURE: A tool errored or timed out. Different parameters might work.
- L2_APPROACH_FAILURE: The approach was wrong. Need to try a completely different technique.
- L3_SCOPE_FAILURE: The target is likely not vulnerable to this attack class.
- L4_SYSTEMATIC_FAILURE: A fundamental issue (e.g., WAF blocks everything, auth required but not available).

Respond in EXACTLY this JSON format:
{
  "is_valid": true/false,
  "failure_level": "" or "L1_TOOL_FAILURE" or "L2_APPROACH_FAILURE" or "L3_SCOPE_FAILURE" or "L4_SYSTEMATIC_FAILURE",
  "reasoning": "concise explanation of what happened",
  "feedback": "specific actionable feedback for retry",
  "suggested_next": "what the Planner should do next",
  "should_retry": true/false,
  "intelligence": "key learnings to save for future scans on similar targets",
  "confidence": 0.0-1.0
}`, execSummary.String())

	resp, err := r.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a strict penetration testing auditor. Analyze execution results objectively. Output valid JSON only."},
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		log.Printf("[reflector] LLM call failed: %v", err)
		return r.fallbackReflection(result), nil
	}

	var reflection ReflectionResult
	content := extractJSON(resp.Content)
	if err := json.Unmarshal([]byte(content), &reflection); err != nil {
		log.Printf("[reflector] Failed to parse LLM response: %v", err)
		return r.heuristicReflection(result, resp.Content), nil
	}

	return &reflection, nil
}

// ValidateFinding asks the Reflector to objectively verify if a finding is proven
// by the execution log. Retains backward compatibility with the old interface.
func (r *Reflector) ValidateFinding(ctx context.Context, systemPrompt string, executionLog []models.ChatMessage, reportedFinding string) (bool, string) {
	var logSummary strings.Builder
	for _, msg := range executionLog {
		if msg.Role == "tool" || msg.Role == "assistant" {
			logSummary.WriteString(fmt.Sprintf("[%s]: %s\n", msg.Role, truncate(msg.Content, 500)))
		}
	}

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

	resp, err := r.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a rigid security auditor. You require hard proof."},
			{Role: "user", Content: prompt},
		},
	})

	if err != nil {
		log.Printf("[reflector] Error calling LLM: %v", err)
		return true, "Reflector LLM failed, automatically accepting."
	}

	content := resp.Content
	valid := strings.Contains(strings.ToUpper(content), "VALID: TRUE")

	reason := "No reason provided."
	parts := strings.SplitAfter(content, "REASON:")
	if len(parts) > 1 {
		reason = strings.TrimSpace(parts[1])
	}

	return valid, reason
}

// ClassifyFailure performs heuristic failure classification without LLM.
func (r *Reflector) ClassifyFailure(result *ExecutionResult) FailureLevel {
	if result == nil || result.Success {
		return FailureNone
	}

	errLower := strings.ToLower(result.Error)

	// L1: Tool-level failures
	if strings.Contains(errLower, "timeout") ||
		strings.Contains(errLower, "connection refused") ||
		strings.Contains(errLower, "sandbox execution failed") {
		return FailureL1Tool
	}

	// L4: Systematic failures (WAF, auth)
	for _, msg := range result.Messages {
		lower := strings.ToLower(msg.Content)
		if strings.Contains(lower, "403 forbidden") ||
			strings.Contains(lower, "waf") ||
			strings.Contains(lower, "blocked") ||
			strings.Contains(lower, "rate limit") {
			return FailureL4Systematic
		}
	}

	// L3: Scope failure (target not vulnerable)
	if result.StepCount > 10 && result.Confidence < 0.3 {
		return FailureL3Scope
	}

	// L2: Default -- approach failure
	return FailureL2Approach
}

// fallbackReflection provides a heuristic result when LLM is unavailable.
func (r *Reflector) fallbackReflection(result *ExecutionResult) *ReflectionResult {
	level := r.ClassifyFailure(result)
	return &ReflectionResult{
		IsValid:      result.Success,
		FailureLevel: level,
		Reasoning:    "Fallback heuristic analysis (LLM unavailable)",
		Feedback:     fmt.Sprintf("Failure classified as %s", level),
		ShouldRetry:  level == FailureL1Tool || level == FailureL2Approach,
		Confidence:   result.Confidence,
	}
}

// heuristicReflection parses a non-JSON LLM response into a ReflectionResult.
func (r *Reflector) heuristicReflection(result *ExecutionResult, rawContent string) *ReflectionResult {
	level := r.ClassifyFailure(result)
	isValid := result.Success

	upper := strings.ToUpper(rawContent)
	if strings.Contains(upper, "VALID: TRUE") || strings.Contains(upper, "\"IS_VALID\": TRUE") {
		isValid = true
	} else if strings.Contains(upper, "VALID: FALSE") || strings.Contains(upper, "\"IS_VALID\": FALSE") {
		isValid = false
	}

	return &ReflectionResult{
		IsValid:      isValid,
		FailureLevel: level,
		Reasoning:    truncate(rawContent, 500),
		Feedback:     "Parsed from non-JSON LLM response",
		ShouldRetry:  !isValid && (level == FailureL1Tool || level == FailureL2Approach),
		Confidence:   result.Confidence,
	}
}

// truncate is defined in compress.go
