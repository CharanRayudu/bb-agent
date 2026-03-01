package llm

import (
	"github.com/bb-agent/mirage/internal/models"
)

// ToolDefinition describes a tool the LLM can call
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// CompletionRequest is the input to the LLM
type CompletionRequest struct {
	Messages    []models.ChatMessage `json:"messages"`
	Tools       []ToolDefinition     `json:"tools,omitempty"`
	Temperature float64              `json:"temperature"`
	Model       string               `json:"model"`
}

// CompletionResponse is the output from the LLM
type CompletionResponse struct {
	Content   string            `json:"content"`
	ToolCalls []models.ToolCall `json:"tool_calls,omitempty"`
	Usage     TokenUsage        `json:"usage"`
}

// TokenUsage tracks token consumption
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Provider is the interface for LLM backends
type Provider interface {
	Complete(req CompletionRequest) (*CompletionResponse, error)
	Name() string
}
