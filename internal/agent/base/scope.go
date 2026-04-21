package base

import "context"

// Scope is the minimal interface used by specialist probe clients (e.g.
// FuzzClient) to refuse out-of-scope HTTP requests. The orchestrator
// implements this via its ScopeEngine and injects it into the request
// context before dispatching specialists.
type Scope interface {
	IsInScope(targetURL string) bool
}

type scopeKey struct{}

// WithScope returns a new context carrying the given Scope. Specialists
// and low-level probe clients retrieve it via ScopeFromContext.
func WithScope(ctx context.Context, s Scope) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFromContext returns the Scope attached to ctx, or nil if none.
// Callers that encounter a nil Scope should fail closed only if the
// deployment requires strict scope enforcement; the default is to allow
// (preserving current test/local behavior).
func ScopeFromContext(ctx context.Context) Scope {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(scopeKey{}).(Scope)
	return s
}
