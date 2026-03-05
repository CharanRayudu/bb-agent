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
	// CompressMessageThreshold triggers compression when chat history exceeds this many messages
	CompressMessageThreshold = 12

	// CompressTokenThreshold triggers compression when estimated tokens exceed this threshold
	CompressTokenThreshold = 80000

	// CompressKeepRecent is the number of most recent messages to keep uncompressed
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

// shouldCompress checks if the conversation needs compression
func shouldCompress(msgs []models.ChatMessage) bool {
	if len(msgs) > CompressMessageThreshold {
		return true
	}
	if estimateTokens(msgs) > CompressTokenThreshold {
		return true
	}
	return false
}

// compressConversation summarizes older messages via LLM, keeping the N most recent.
// Returns the compressed message list: [compressed_summary] + recent messages.
func (o *Orchestrator) compressConversation(ctx context.Context, msgs []models.ChatMessage, keepRecent int) []models.ChatMessage {
	if len(msgs) <= keepRecent {
		return msgs // Nothing to compress
	}

	// Split into older (to compress) and recent (to keep)
	older := msgs[:len(msgs)-keepRecent]
	recent := msgs[len(msgs)-keepRecent:]

	// Build a summary of older messages for the LLM
	var sb strings.Builder
	for _, m := range older {
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
		"Summarize this penetration testing conversation in 400 words or less. "+
			"Focus on: (1) Key discoveries and findings, (2) Tools used and their results, "+
			"(3) Failed attempts and why they failed, (4) Current strategy and next steps. "+
			"Be specific about URLs, parameters, and vulnerability types.\n\n"+
			"CONVERSATION:\n%s", sb.String(),
	)

	resp, err := o.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "user", Content: summaryPrompt},
		},
	})

	if err != nil {
		log.Printf("[compress] Failed to summarize conversation: %v", err)
		// Fallback: just keep recent + first message
		if len(msgs) > 0 {
			return append([]models.ChatMessage{msgs[0]}, recent...)
		}
		return recent
	}

	summary := resp.Content
	if summary == "" {
		log.Printf("[compress] LLM returned empty summary, keeping original messages")
		return msgs
	}

	// Build compressed messages: summary + recent
	compressed := make([]models.ChatMessage, 0, 1+len(recent))
	compressed = append(compressed, models.ChatMessage{
		Role: "user",
		Content: fmt.Sprintf("📊 COMPRESSED CONTEXT (summarized from %d earlier messages):\n\n%s",
			len(older), summary),
	})
	compressed = append(compressed, recent...)

	log.Printf("[compress] Compressed %d messages → 1 summary + %d recent = %d total",
		len(older), len(recent), len(compressed))

	return compressed
}

// truncate safely truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
