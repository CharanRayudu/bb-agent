package policy

import (
	"sync"
	"time"
)

// Book is the in-process set of authorization records.
// PostgreSQL persistence is handled by the execution store; this book is the
// copy the gateway and trigger paths consult.
type Book struct {
	mu     sync.Mutex
	byFlow map[string]*Authorization
	order  []*Authorization
}

func NewBook() *Book {
	return &Book{byFlow: map[string]*Authorization{}}
}

// Put stores an authorization and returns the canonical pointer.
func (b *Book) Put(auth Authorization) *Authorization {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.byFlow[auth.FlowID]; ok && auth.FlowID != "" {
		*existing = auth
		return existing
	}
	stored := new(Authorization)
	*stored = auth
	if auth.FlowID != "" {
		b.byFlow[auth.FlowID] = stored
	}
	b.order = append(b.order, stored)
	return stored
}

func (b *Book) Snapshot(flowID string) (Authorization, bool) {
	if b == nil {
		return Authorization{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	auth, ok := b.byFlow[flowID]
	if !ok || auth == nil {
		return Authorization{}, false
	}
	return *auth, true
}

// Get returns the canonical record for a flow, if one was stored.
func (b *Book) Get(flowID string) *Authorization {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.byFlow[flowID]
}

// All returns a copy of every stored authorization.
func (b *Book) All() []Authorization {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Authorization, 0, len(b.order))
	for _, auth := range b.order {
		if auth != nil {
			out = append(out, *auth)
		}
	}
	return out
}

// TryConsume increments the request counter when budget remains.
// A zero MaxRequests means unlimited.
func (b *Book) TryConsume(flowID string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	auth := b.byFlow[flowID]
	if auth == nil {
		return false
	}
	if auth.MaxRequests > 0 && auth.RequestsUsed >= auth.MaxRequests {
		return false
	}
	auth.RequestsUsed++
	return true
}

// AuthorizeStart is the check used by scheduled scans and CI triggers.
// Interactive flow creation mints a record; these paths must match one that
// already exists.
func (b *Book) AuthorizeStart(target string, now time.Time) Decision {
	if b == nil {
		return deny(CodeAuthorizationMissing, "no authorization book is configured")
	}
	parsed, err := ParseTarget(target)
	if err != nil {
		return deny(CodeInvalidTarget, err.Error())
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return deny(CodeAuthorizationMissing, "no authorization record covers this target")
	}
	for _, auth := range b.order {
		if auth == nil {
			continue
		}
		if !auth.NotBefore.IsZero() && now.Before(auth.NotBefore) {
			continue
		}
		if !auth.ExpiresAt.IsZero() && !now.Before(auth.ExpiresAt) {
			continue
		}
		if authorizedHost(*auth, parsed.Host) && authorizedPort(*auth, parsed.Host, effectivePort(parsed.Port, parsed.Scheme), parsed.Scheme) && !excluded(*auth, parsed.Host, effectivePort(parsed.Port, parsed.Scheme), parsed.Scheme) {
			return Decision{Allowed: true, Code: CodeAuthorized, Reason: "trigger matches authorization " + auth.ID}
		}
	}
	return deny(CodeOutOfScope, "target is not covered by an unexpired authorization record")
}

// Match returns the authorization a scheduled or CI scan must inherit.
func (b *Book) Match(target string, now time.Time) (Authorization, bool) {
	if b == nil {
		return Authorization{}, false
	}
	parsed, err := ParseTarget(target)
	if err != nil {
		return Authorization{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, auth := range b.order {
		if auth == nil || !windowOpen(*auth, now) {
			continue
		}
		port := effectivePort(parsed.Port, parsed.Scheme)
		if authorizedHost(*auth, parsed.Host) && authorizedPort(*auth, parsed.Host, port, parsed.Scheme) && !excluded(*auth, parsed.Host, port, parsed.Scheme) {
			return *auth, true
		}
	}
	return Authorization{}, false
}

func windowOpen(auth Authorization, now time.Time) bool {
	if !auth.NotBefore.IsZero() && now.Before(auth.NotBefore) {
		return false
	}
	if !auth.ExpiresAt.IsZero() && !now.Before(auth.ExpiresAt) {
		return false
	}
	return true
}

// CloneForFlow copies restrictions onto a new flow without widening them.
func (a Authorization) CloneForFlow(flowID string) Authorization {
	clone := a
	clone.ID = "auth:" + flowID
	clone.FlowID = flowID
	if clone.EngagementID == "" {
		clone.EngagementID = a.FlowID
	}
	clone.RequestsUsed = 0
	clone.InFlight = 0
	return clone
}

// Revoke expires an authorization immediately.
func (b *Book) Revoke(id string, now time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, auth := range b.order {
		if auth != nil && auth.ID == id {
			auth.ExpiresAt = now
			return true
		}
	}
	return false
}
