package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
)

// ExecutionResult captures the outcome of a single executor run.
type ExecutionResult struct {
	Success      bool             `json:"success"`
	Findings     []*Finding       `json:"findings,omitempty"`
	ToolsUsed    []string         `json:"tools_used"`
	StepCount    int              `json:"step_count"`
	TokensUsed   int              `json:"tokens_used"`
	Duration     time.Duration    `json:"duration"`
	Error        string           `json:"error,omitempty"`
	Confidence   float64          `json:"confidence"`
	Messages     []models.ChatMessage `json:"messages,omitempty"`
	FailureClass FailureLevel     `json:"failure_class,omitempty"`
}

// Executor handles tactical execution of individual sub-tasks.
// It orchestrates tools, manages context compression, and reports results.
type Executor struct {
	llmProvider  llm.Provider
	toolRegistry *tools.Registry
	bus          *EventBus
	confidence   *ConfidenceEngine
	maxSteps     int
}

// NewExecutor creates a new tactical Executor.
func NewExecutor(provider llm.Provider, registry *tools.Registry, bus *EventBus) *Executor {
	return &Executor{
		llmProvider:  provider,
		toolRegistry: registry,
		bus:          bus,
		confidence:   NewConfidenceEngine(DefaultConfidenceThresholds()),
		maxSteps:     maxIterations,
	}
}

// ExecuteTask runs a single specialist task using the ReAct loop with
// confidence-driven reasoning. Returns the execution result for the
// Reflector to analyze.
func (e *Executor) ExecuteTask(ctx context.Context, flowID, taskID, subtaskID uuid.UUID,
	systemPrompt, userPrompt string, brain *Brain, brainMu *sync.Mutex,
	onEvent EventHandler) *ExecutionResult {

	start := time.Now()
	result := &ExecutionResult{
		ToolsUsed: make([]string, 0),
	}

	messages := []models.ChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	toolDefs := e.toolRegistry.Definitions()
	completionSignal := false

	for step := 0; step < e.maxSteps && !completionSignal; step++ {
		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			result.Duration = time.Since(start)
			return result
		default:
		}

		resp, err := e.llmProvider.Complete(ctx, llm.CompletionRequest{
			Messages: messages,
			Tools:    toolDefs,
		})
		if err != nil {
			result.Error = fmt.Sprintf("LLM call failed at step %d: %v", step, err)
			result.Duration = time.Since(start)
			return result
		}

		result.TokensUsed += resp.Usage.TotalTokens
		result.StepCount = step + 1

		if resp.Content != "" {
			messages = append(messages, models.ChatMessage{
				Role:    "assistant",
				Content: resp.Content,
			})
			if onEvent != nil {
				onEvent(Event{
					Type:    EventThinking,
					FlowID:  flowID.String(),
					TaskID:  taskID.String(),
					Content: resp.Content,
				})
			}
		}

		if len(resp.ToolCalls) == 0 {
			break
		}

		assistantMsg := models.ChatMessage{
			Role:      "assistant",
			ToolCalls: resp.ToolCalls,
		}
		if resp.Content != "" {
			assistantMsg.Content = resp.Content
		}
		messages = append(messages, assistantMsg)

		for _, tc := range resp.ToolCalls {
			result.ToolsUsed = append(result.ToolsUsed, tc.Name)

			if onEvent != nil {
				onEvent(Event{
					Type:    EventToolCall,
					FlowID:  flowID.String(),
					TaskID:  taskID.String(),
					Content: fmt.Sprintf("%s(%s)", tc.Name, truncateArgs(tc.Arguments)),
				})
			}

			toolOutput := e.executeTool(ctx, tc, brain, brainMu, &completionSignal)

			messages = append(messages, models.ChatMessage{
				Role:       "tool",
				Content:    toolOutput,
				ToolCallID: tc.ID,
			})

			if onEvent != nil {
				onEvent(Event{
					Type:    EventToolResult,
					FlowID:  flowID.String(),
					TaskID:  taskID.String(),
					Content: truncate(toolOutput, 500),
				})
			}
		}

		// Context compression: if messages are getting long, summarize older ones
		if len(messages) > 40 {
			messages = e.compressContext(messages)
		}
	}

	result.Success = completionSignal || len(result.ToolsUsed) > 0
	result.Duration = time.Since(start)
	result.Messages = messages
	result.Confidence = e.assessConfidence(messages)

	return result
}

// executeTool runs a single tool call and returns the output.
func (e *Executor) executeTool(ctx context.Context, tc models.ToolCall, brain *Brain, brainMu *sync.Mutex, completionSignal *bool) string {
	if tc.Name == "complete_task" {
		*completionSignal = true
	}

	tool, ok := e.toolRegistry.Get(tc.Name)
	if !ok {
		return fmt.Sprintf("[ERROR] Tool '%s' not found in registry", tc.Name)
	}

	output, err := tool.Execute(ctx, json.RawMessage(tc.Arguments))
	if err != nil {
		return fmt.Sprintf("[ERROR] %s failed: %v", tc.Name, err)
	}

	return output
}

// compressContext summarizes older messages to keep the context window manageable.
func (e *Executor) compressContext(messages []models.ChatMessage) []models.ChatMessage {
	if len(messages) <= 10 {
		return messages
	}

	// Keep system prompt and last 20 messages, summarize the middle
	systemMsgs := make([]models.ChatMessage, 0)
	for _, m := range messages {
		if m.Role == "system" {
			systemMsgs = append(systemMsgs, m)
		}
	}

	midStart := len(systemMsgs)
	midEnd := len(messages) - 20
	if midEnd <= midStart {
		return messages
	}

	var summary strings.Builder
	summary.WriteString("[COMPRESSED CONTEXT - Earlier steps summarized]\n")
	toolCounts := make(map[string]int)
	for _, m := range messages[midStart:midEnd] {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				toolCounts[tc.Name]++
			}
		}
	}
	for tool, count := range toolCounts {
		summary.WriteString(fmt.Sprintf("- Used %s x%d\n", tool, count))
	}

	compressed := make([]models.ChatMessage, 0, len(systemMsgs)+1+20)
	compressed = append(compressed, systemMsgs...)
	compressed = append(compressed, models.ChatMessage{
		Role:    "user",
		Content: summary.String(),
	})
	compressed = append(compressed, messages[midEnd:]...)

	log.Printf("[executor] Compressed context from %d to %d messages", len(messages), len(compressed))
	return compressed
}

// assessConfidence estimates the overall confidence of the execution result
// based on what tools were used and the message content.
func (e *Executor) assessConfidence(messages []models.ChatMessage) float64 {
	confidence := 0.3 // base
	hasProof := false
	hasToolExecution := false

	for _, m := range messages {
		lower := strings.ToLower(m.Content)
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			hasToolExecution = true
		}
		if strings.Contains(lower, "confirmed") || strings.Contains(lower, "verified") || strings.Contains(lower, "proof") {
			hasProof = true
		}
		if strings.Contains(lower, "complete_task") {
			confidence += 0.2
		}
	}

	if hasToolExecution {
		confidence += 0.2
	}
	if hasProof {
		confidence += 0.3
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func truncateArgs(args string) string {
	if len(args) > 100 {
		return args[:100] + "..."
	}
	return args
}
