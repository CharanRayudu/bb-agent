package agent

import (
	"context"
	"testing"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

func TestShouldCompressSkipsUnresolvedToolCall(t *testing.T) {
	msgs := []models.ChatMessage{
		{Role: "user", Content: "recon"},
		{Role: "assistant", Content: "", ToolCalls: []models.ToolCall{{ID: "call_1", Name: "think", Arguments: `{"thought":"x"}`}}},
		{Role: "assistant", Content: "follow-up"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
		{Role: "assistant", Content: "more"},
	}

	if shouldCompress(msgs) {
		t.Fatal("expected unresolved tool calls to disable compression")
	}
}

func TestCompressConversationPreservesToolStateMessages(t *testing.T) {
	stub := &StubProvider{
		Responses: []*llm.CompletionResponse{
			{Content: "summary"},
		},
	}
	orch := &Orchestrator{llmProvider: stub}

	msgs := []models.ChatMessage{
		{Role: "user", Content: "Initial recon"},
		{Role: "assistant", Content: "Reasoning before a tool call"},
		{Role: "assistant", Content: "", ToolCalls: []models.ToolCall{{ID: "call_1", Name: "execute_command", Arguments: `{"command":"curl http://example.com"}`}}},
		{Role: "tool", Content: "HTTP 200", ToolCallID: "call_1"},
		{Role: "assistant", Content: "Post-tool analysis"},
		{Role: "user", Content: "Keep going"},
		{Role: "assistant", Content: "Recent message"},
	}

	compressed := orch.compressConversation(context.Background(), msgs, 2)
	if len(compressed) != 6 {
		t.Fatalf("expected 6 messages after compression, got %d", len(compressed))
	}
	if compressed[1].ToolCalls[0].ID != "call_1" {
		t.Fatalf("expected tool call message to be preserved, got %+v", compressed[1])
	}
	if compressed[2].ToolCallID != "call_1" {
		t.Fatalf("expected matching tool result to be preserved, got %+v", compressed[2])
	}
	if compressed[0].Content == "" {
		t.Fatal("expected summary message to be present")
	}
	if compressed[3].Content == "" {
		t.Fatal("expected post-tool summary message to be present")
	}
}
