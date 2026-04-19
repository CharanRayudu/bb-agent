package agent

import (
	"context"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/llm"
)

// LLMMutator wraps an LLM provider to produce context-aware payload mutations.
// It is defined here as a type alias for base.LLMMutator so the agent package
// exposes it under the agent namespace while avoiding import cycles
// (agents/wafevasion imports agent/base, not agent).
type LLMMutator = base.LLMMutator

// NewLLMMutator creates a new LLMMutator backed by the given provider.
func NewLLMMutator(provider llm.Provider, model string) *LLMMutator {
	return base.NewLLMMutator(provider, model)
}

// LLMEnhancedMutate uses the LLM to generate intelligent, context-aware payload variants.
// Falls back to rule-based mutation if LLM is unavailable.
func LLMEnhancedMutate(ctx context.Context, llmProvider llm.Provider, payload, vulnType, techStack, wafVendor string) []string {
	return base.LLMEnhancedMutate(ctx, llmProvider, payload, vulnType, techStack, wafVendor)
}

// MutatePayload applies simple rule-based mutations to a payload string.
func MutatePayload(payload string, strategy PayloadMutationStrategy) []string {
	pe := &PayloadEngine{}
	return pe.MutatePayload(payload, strategy)
}
