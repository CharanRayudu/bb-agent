package llm

import (
	"context"
	"fmt"
	"sync"
)

// GuardedProvider stops repeating permanently unsupported model calls.
type GuardedProvider struct {
	base    Provider
	choice  Selection
	mu      sync.Mutex
	blocked error
}

// NewGuardedProvider wraps a provider with a permanent-failure circuit breaker.
func NewGuardedProvider(base Provider, choice Selection) *GuardedProvider {
	return &GuardedProvider{base: base, choice: choice}
}

func (g *GuardedProvider) Name() string {
	if g == nil || g.base == nil {
		return "guarded"
	}
	return g.base.Name()
}

// Selection returns the recorded provider choice.
func (g *GuardedProvider) Selection() Selection {
	if g == nil {
		return Selection{}
	}
	return g.choice
}

func (g *GuardedProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	g.mu.Lock()
	blocked := g.blocked
	g.mu.Unlock()
	if blocked != nil {
		return nil, blocked
	}
	resp, err := g.base.Complete(ctx, req)
	if err != nil && IsPermanentModelError(err) {
		permanent := fmt.Errorf("permanent llm failure for model %s via %s: %w", g.choice.Model, g.choice.Source, err)
		g.mu.Lock()
		g.blocked = permanent
		g.mu.Unlock()
		return nil, permanent
	}
	return resp, err
}
