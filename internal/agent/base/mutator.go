package base

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// LLMMutator wraps an LLM provider to produce context-aware payload mutations.
type LLMMutator struct {
	Provider llm.Provider
	Model    string
}

// NewLLMMutator creates a new LLMMutator backed by the given provider.
func NewLLMMutator(provider llm.Provider, model string) *LLMMutator {
	return &LLMMutator{Provider: provider, Model: model}
}

// Mutate generates LLM-driven payload variants for WAF bypass.
// context is a free-form string that may contain WAF vendor, tech stack, or other hints.
func (m *LLMMutator) Mutate(ctx context.Context, payload, vulnType, context string) []string {
	return LLMEnhancedMutate(ctx, m.Provider, payload, vulnType, context, "")
}

// LLMEnhancedMutate uses the LLM to generate intelligent, context-aware payload variants.
// Falls back to an empty list if LLM is unavailable.
func LLMEnhancedMutate(ctx context.Context, llmProvider llm.Provider, payload, vulnType, techStack, wafVendor string) []string {
	if llmProvider == nil {
		return nil
	}

	wafContext := "unknown"
	if wafVendor != "" {
		wafContext = wafVendor
	}
	stackContext := "generic"
	if techStack != "" {
		stackContext = techStack
	}

	prompt := fmt.Sprintf(`Generate 5 WAF-bypass variants of the following payload.

Payload: %s
Vulnerability Type: %s
Tech Stack: %s
WAF Vendor: %s

Instructions:
1. Generate exactly 5 WAF-bypass payload variants.
2. Consider the tech stack (%s) for syntax choices.
3. Consider the WAF vendor (%s) for bypass techniques.
4. Return ONLY the payload variants, one per line, no explanation, no numbering.`,
		payload, vulnType, stackContext, wafContext, stackContext, wafContext)

	resp, err := llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a WAF bypass expert. Return only payload variants, one per line, no explanations."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.7,
	})
	if err != nil {
		return nil
	}

	return parseLLMMutationResponse(resp.Content)
}

func parseLLMMutationResponse(content string) []string {
	lines := strings.Split(content, "\n")
	var variants []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || len(trimmed) > 2000 {
			continue
		}
		variants = append(variants, trimmed)
		if len(variants) >= 5 {
			break
		}
	}
	return variants
}
