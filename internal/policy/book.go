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
	spent  map[string]int
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
		b.syncSpend(existing)
		return existing
	}
	stored := new(Authorization)
	*stored = auth
	if auth.FlowID != "" {
		b.byFlow[auth.FlowID] = stored
	}
	b.order = append(b.order, stored)
	b.syncSpend(stored)
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
	key := engagementKey(auth)
	if b.spent == nil {
		b.spent = map[string]int{}
	}
	used := b.spent[key]
	if auth.MaxRequests > 0 && used >= auth.MaxRequests {
		return false
	}
	b.spent[key] = used + 1
	for _, other := range b.order {
		if other != nil && engagementKey(other) == key {
			other.RequestsUsed = b.spent[key]
		}
	}
	return true
}

func (b *Book) syncSpend(auth *Authorization) {
	if auth == nil {
		return
	}
	if b.spent == nil {
		b.spent = map[string]int{}
	}
	key := engagementKey(auth)
	if prev, ok := b.spent[key]; ok && prev > auth.RequestsUsed {
		auth.RequestsUsed = prev
	}
	b.spent[key] = auth.RequestsUsed
	for _, other := range b.order {
		if other != nil && engagementKey(other) == key {
			other.RequestsUsed = b.spent[key]
		}
	}
}

func engagementKey(auth *Authorization) string {
	if auth == nil {
		return ""
	}
	if auth.EngagementID != "" {
		return auth.EngagementID
	}
	return auth.FlowID
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
	clone.InFlight = 0
	return clone
}

// Revoke expires an authorization and every flow cloned from the same engagement.
func (b *Book) Revoke(id string, now time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var matched *Authorization
	for _, auth := range b.order {
		if auth != nil && (auth.ID == id || auth.FlowID == id) {
			matched = auth
			break
		}
	}
	if matched == nil {
		return false
	}
	key := engagementKey(matched)
	for _, auth := range b.order {
		if auth != nil && engagementKey(auth) == key {
			auth.ExpiresAt = now
		}
	}
	return true
}
