package agent

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

const (
	// CompressMessageThreshold triggers compression when chat history exceeds this many messages.
	CompressMessageThreshold = 12

	// CompressTokenThreshold triggers compression when estimated tokens exceed this threshold.
	CompressTokenThreshold = 80000

	// CompressKeepRecent is the number of most recent messages to keep uncompressed.
	CompressKeepRecent = 6
)

// estimateTokens rough-estimates the token count of a message list.
// Uses the ~4 chars per token heuristic.
func estimateTokens(msgs []models.ChatMessage) int {
	total := 0
	for _, m := range msgs {
		total += len(m.Content)
		for _, tc := range m.ToolCalls {
			total += len(tc.Arguments)
		}
	}
	return total / 4
}

func hasUnresolvedToolCalls(msgs []models.ChatMessage) bool {
	pending := make(map[string]struct{})
	for _, m := range msgs {
		for _, tc := range m.ToolCalls {
			if tc.ID != "" {
				pending[tc.ID] = struct{}{}
			}
		}
		if m.Role == "tool" && m.ToolCallID != "" {
			delete(pending, m.ToolCallID)
		}
	}
	return len(pending) > 0
}

func isToolStateMessage(m models.ChatMessage) bool {
	return len(m.ToolCalls) > 0 || (m.Role == "tool" && m.ToolCallID != "")
}

func hasCompressibleMessages(msgs []models.ChatMessage, keepRecent int) bool {
	if len(msgs) <= keepRecent {
		return false
	}

	for _, m := range msgs[:len(msgs)-keepRecent] {
		if !isToolStateMessage(m) {
			return true
		}
	}

	return false
}

// shouldCompress checks if the conversation needs compression.
func shouldCompress(msgs []models.ChatMessage) bool {
	if hasUnresolvedToolCalls(msgs) {
		return false
	}
	if !hasCompressibleMessages(msgs, CompressKeepRecent) {
		return false
	}
	if len(msgs) > CompressMessageThreshold {
		return true
	}
	if estimateTokens(msgs) > CompressTokenThreshold {
		return true
	}
	return false
}

// compressConversation summarizes older non-tool messages via LLM, while preserving
// assistant tool call messages and matching tool-result messages exactly. It ensures
// that the precise order of (assistant -> tool) sequences is inherently maintained.
func (o *Orchestrator) compressConversation(ctx context.Context, msgs []models.ChatMessage, keepRecent int) []models.ChatMessage {
	if len(msgs) <= keepRecent {
		return msgs
	}
	if hasUnresolvedToolCalls(msgs) {
		log.Printf("[compress] Skipping compression because tool call history is incomplete")
		return msgs
	}

	older := msgs[:len(msgs)-keepRecent]
	recent := msgs[len(msgs)-keepRecent:]
	compressed := make([]models.ChatMessage, 0)

	var currentCompressible []models.ChatMessage
	var totalCompressed, totalProtected int

	// Helper to flush current compressible chunk into a summary message
	flushCompressible := func() {
		if len(currentCompressible) == 0 {
			return
		}
		var sb strings.Builder
		for _, m := range currentCompressible {
			switch m.Role {
			case "user":
				sb.WriteString(fmt.Sprintf("[User]: %s\n", truncate(m.Content, 500)))
			case "assistant":
				sb.WriteString(fmt.Sprintf("[Agent]: %s\n", truncate(m.Content, 500)))
			case "tool":
				sb.WriteString(fmt.Sprintf("[Tool Result]: %s\n", truncate(m.Content, 300)))
			}
		}

		summaryPrompt := fmt.Sprintf(
			"Summarize this part of the conversation in 200 words or less. "+
				"Focus on: (1) Key discoveries, (2) Strategy and reasoning. "+
				"Be specific about URLs, parameters, and vulnerability types.\n\n"+
				"CONVERSATION CHUNK:\n%s", sb.String(),
		)

		resp, err := o.llmProvider.Complete(ctx, llm.CompletionRequest{
			Messages: []models.ChatMessage{
				{Role: "user", Content: summaryPrompt},
			},
		})

		var summary string
		if err != nil {
			log.Printf("[compress] Failed to summarize chunk: %v", err)
			summary = "[Summary failed, context omitted to save tokens]"
		} else {
			summary = resp.Content
		}

		if summary != "" {
			compressed = append(compressed, models.ChatMessage{
				Role: "user",
				Content: fmt.Sprintf("Compressed context summary (%d earlier reasoning messages):\n\n%s",
					len(currentCompressible), summary),
			})
		}

		totalCompressed += len(currentCompressible)
		currentCompressible = nil
	}

	// Walk over the older messages
	for _, m := range older {
		if isToolStateMessage(m) {
			// A tool message boundary is reached. Flush pending compressibles first.
			flushCompressible()
			compressed = append(compressed, m)
			totalProtected++
		} else {
			// Accumulate compressible reasoning messages
			currentCompressible = append(currentCompressible, m)
		}
	}

	// Flush any trailing compressibles
	flushCompressible()

	// Append the uncompressed recent messages
	compressed = append(compressed, recent...)

	log.Printf("[compress] Compressed %d reasoning messages into blocks, preserved %d tool-state messages exactly in order, kept %d recent = %d total",
		totalCompressed, totalProtected, len(recent), len(compressed))

	return compressed
}

// truncate safely truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
