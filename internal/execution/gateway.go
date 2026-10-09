package execution

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
	"github.com/google/uuid"
)

var (
	ErrDenied          = errors.New("action denied")
	ErrGatewayRequired = errors.New("execution gateway required")
	ErrCancelled       = errors.New("action cancelled")
)

// Resolver looks up a hostname at execution time.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// NetResolver uses the process resolver. IP literals are returned as-is.
type NetResolver struct{}

func (NetResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// Runner performs an action that has already been authorized.
type Runner func(context.Context, Action) (string, error)

// Gateway is the only component that may release an action to a tool or socket.
type Gateway struct {
	book      *policy.Book
	store     Store
	resolver  Resolver
	engine    policy.Engine
	auth      *policy.Authorization
	now       func() time.Time
	cancelled map[string]bool
	status    map[string]Status
	lock      chan struct{}
}

func NewGateway(book *policy.Book, store Store, resolver Resolver) *Gateway {
	if book == nil {
		book = policy.NewBook()
	}
	if store == nil {
		store = NewMemoryStore()
	}
	if resolver == nil {
		resolver = NetResolver{}
	}
	return &Gateway{
		book:      book,
		store:     store,
		resolver:  resolver,
		now:       time.Now,
		cancelled: map[string]bool{},
		status:    map[string]Status{},
		lock:      make(chan struct{}, 1),
	}
}

func (g *Gateway) hold() func() {
	g.lock <- struct{}{}
	return func() { <-g.lock }
}

// SetClock overrides the clock used for windows and approval expiry.
func (g *Gateway) SetClock(now func() time.Time) {
	if now != nil {
		g.now = now
	}
}

// WithAuthorization binds a copy of the gateway at one engagement record.
// The book and audit store stay shared.
func (g *Gateway) WithAuthorization(auth *policy.Authorization) *Gateway {
	if g == nil {
		return nil
	}
	cp := *g
	cp.auth = auth
	return &cp
}

func (g *Gateway) Store() Store {
	if g == nil {
		return nil
	}
	return g.store
}

// Authorize resolves the destination, re-resolves it, and persists the decision.
// It does not call a transport.
func (g *Gateway) Authorize(ctx context.Context, action Action) (Decision, error) {
	if g == nil {
		return Decision{}, ErrGatewayRequired
	}
	action = g.prepare(action)
	if g.isCancelled(action.ID) {
		d := g.persist(action, policy.Decision{Allowed: false, Code: "cancelled", Reason: "action was cancelled"})
		g.remember(action.ID, "cancelled", d)
		return d, ErrCancelled
	}
	first, err := g.evaluate(ctx, action)
	if err != nil {
		return Decision{}, err
	}
	if !first.Allowed {
		d1 := g.persist(action, first)
		g.remember(action.ID, "denied", d1)
		return d1, ErrDenied
	}
	second, err := g.evaluate(ctx, action)
	if err != nil {
		return Decision{}, err
	}
	if !second.Allowed {
		d2 := g.persist(action, second)
		g.remember(action.ID, "denied", d2)
		return d2, ErrDenied
	}
	if !g.consume(action.FlowID) {
		denied := g.persist(action, policy.Decision{Allowed: false, Code: policy.CodeBudgetExhausted, Reason: "request budget for this authorization is exhausted"})
		g.remember(action.ID, "denied", denied)
		return denied, ErrDenied
	}
	d2 := g.persist(action, second)
	g.remember(action.ID, "authorized", d2)
	return d2, nil
}

func (g *Gateway) consume(flowID string) bool {
	if _, ok := g.book.Snapshot(flowID); ok {
		return g.book.TryConsume(flowID)
	}
	if g.auth != nil && (flowID == "" || g.auth.FlowID == flowID) {
		if g.auth.MaxRequests > 0 && g.auth.RequestsUsed >= g.auth.MaxRequests {
			return false
		}
		g.auth.RequestsUsed++
		return true
	}
	return false
}

// Execute authorizes an action and only then calls run.
func (g *Gateway) Execute(ctx context.Context, action Action, run Runner) (Result, error) {
	if action.ID == "" {
		action.ID = uuid.NewString()
	}
	decision, err := g.Authorize(ctx, action)
	if err != nil {
		return Result{Decision: decision, Output: decision.Reason}, err
	}
	if run == nil {
		g.remember(action.ID, "authorized", decision)
		return Result{Decision: decision}, nil
	}
	output, runErr := run(ctx, action)
	state := "completed"
	if runErr != nil {
		state = "failed"
	}
	g.remember(action.ID, state, decision)
	return Result{Decision: decision, Output: output}, runErr
}

// ExecuteTool classifies a model tool call and refuses to run it when denied.
func (g *Gateway) ExecuteTool(ctx context.Context, flowID, name, actor string, args []byte, run func(context.Context) (string, error)) (string, error) {
	action := ToolAction(flowID, name, actor, args)
	result, err := g.Execute(ctx, action, func(ctx context.Context, _ Action) (string, error) {
		if run == nil {
			return "", nil
		}
		return run(ctx)
	})
	if err != nil {
		if result.Output != "" {
			return result.Output, err
		}
		return "", err
	}
	return result.Output, nil
}

// Cancel marks an action so a later Execute cannot reach a transport.
func (g *Gateway) Cancel(_ context.Context, actionID string) error {
	if g == nil || actionID == "" {
		return fmt.Errorf("missing action id")
	}
	unlock := g.hold()
	g.cancelled[actionID] = true
	unlock()
	return nil
}

// GetStatus returns the last recorded state for an action.
func (g *Gateway) GetStatus(_ context.Context, actionID string) (Status, error) {
	if g == nil {
		return Status{}, ErrGatewayRequired
	}
	unlock := g.hold()
	defer unlock()
	st, ok := g.status[actionID]
	if !ok {
		return Status{ActionID: actionID, State: "unknown"}, nil
	}
	return st, nil
}

// GrantPhase records a phase-wide approval or denial on the shared store.
func (g *Gateway) GrantPhase(flowID, phase, actor, status, reason string, ttl time.Duration) (policy.Approval, error) {
	if g == nil {
		return policy.Approval{}, ErrGatewayRequired
	}
	now := g.now()
	approval := policy.Approval{
		ID:        uuid.NewString(),
		FlowID:    flowID,
		Phase:     phase,
		Status:    status,
		Actor:     actor,
		Reason:    reason,
		CreatedAt: now,
	}
	if status == "approved" && ttl > 0 {
		approval.ExpiresAt = now.Add(ttl)
	}
	if err := g.store.SaveApproval(approval); err != nil {
		return policy.Approval{}, err
	}
	return approval, nil
}

// ResolveApproval updates a pending approval. Denied and expired decisions stay denied.
func (g *Gateway) ResolveApproval(id, actor, status, reason string, ttl time.Duration) (policy.Approval, error) {
	if g == nil {
		return policy.Approval{}, ErrGatewayRequired
	}
	var current policy.Approval
	found := false
	for _, candidate := range g.allApprovals() {
		if candidate.ID == id {
			current = candidate
			found = true
			break
		}
	}
	if !found {
		return policy.Approval{}, fmt.Errorf("approval %s not found", id)
	}
	current.Status = status
	current.Actor = actor
	current.Reason = reason
	if status == "approved" && ttl > 0 {
		current.ExpiresAt = g.now().Add(ttl)
	}
	if err := g.store.SaveApproval(current); err != nil {
		return policy.Approval{}, err
	}
	return current, nil
}

func (g *Gateway) allApprovals() []policy.Approval {
	switch store := g.store.(type) {
	case *MemoryStore:
		return store.allLocked()
	case *sqlStore:
		return store.mem.allLocked()
	default:
		return nil
	}
}

func (s *MemoryStore) allLocked() []policy.Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]policy.Approval, len(s.approvals))
	copy(out, s.approvals)
	return out
}

func (g *Gateway) prepare(action Action) Action {
	if action.ID == "" {
		action.ID = uuid.NewString()
	}
	if action.FlowID == "" && g.auth != nil {
		action.FlowID = g.auth.FlowID
	}
	if action.EngagementID == "" {
		action.EngagementID = action.FlowID
	}
	if action.IdempotencyKey == "" {
		action.IdempotencyKey = action.FlowID + ":" + action.ActionType + ":" + action.Host
	}
	return action
}

func (g *Gateway) evaluate(ctx context.Context, action Action) (policy.Decision, error) {
	auth := g.auth
	if auth == nil && action.FlowID != "" {
		if snap, ok := g.book.Snapshot(action.FlowID); ok {
			auth = &snap
		}
	} else if auth != nil && action.FlowID != "" {
		if snap, ok := g.book.Snapshot(action.FlowID); ok {
			auth = &snap
		}
	}
	ips, err := g.resolve(ctx, action)
	if err != nil {
		return policy.Decision{Allowed: false, Code: "dns_failed", Reason: err.Error()}, nil
	}
	var approval *policy.Approval
	if match, ok := g.matchApproval(action); ok {
		approval = &match
	}
	decision := g.engine.Decide(auth, action.subject(ips), approval, g.now())
	if decision.Code == policy.CodeApprovalRequired {
		if _, err := g.ensurePending(action); err != nil {
			return policy.Decision{}, err
		}
	}
	return decision, nil
}

func (g *Gateway) resolve(ctx context.Context, action Action) ([]string, error) {
	if action.Local || action.Host == "" {
		return nil, nil
	}
	if ip := net.ParseIP(action.Host); ip != nil {
		return []string{ip.String()}, nil
	}
	if g.resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}
	found, err := g.resolver.LookupIP(ctx, action.Host)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no addresses for %s", action.Host)
	}
	out := make([]string, 0, len(found))
	for _, ip := range found {
		out = append(out, ip.String())
	}
	return out, nil
}

func (g *Gateway) matchApproval(action Action) (policy.Approval, bool) {
	var phaseHit *policy.Approval
	for _, approval := range g.store.ApprovalsForFlow(action.FlowID) {
		if approval.ActionKey != "" && approval.ActionKey == action.IdempotencyKey {
			return approval, true
		}
		if approval.ActionKey == "" && approval.Phase != "" && approval.Phase == action.Phase {
			cp := approval
			phaseHit = &cp
		}
	}
	if phaseHit != nil {
		return *phaseHit, true
	}
	return policy.Approval{}, false
}

func (g *Gateway) ensurePending(action Action) (policy.Approval, error) {
	if existing, ok := g.matchApproval(action); ok {
		return existing, nil
	}
	approval := policy.Approval{
		ID:        uuid.NewString(),
		FlowID:    action.FlowID,
		ActionKey: action.IdempotencyKey,
		Phase:     action.Phase,
		Status:    "pending",
		Reason:    "waiting for operator approval",
		CreatedAt: g.now(),
	}
	if err := g.store.SaveApproval(approval); err != nil {
		return policy.Approval{}, err
	}
	return approval, nil
}

func (g *Gateway) persist(action Action, d policy.Decision) Decision {
	out := Decision{
		ID:             uuid.NewString(),
		ActionID:       action.ID,
		FlowID:         action.FlowID,
		Allowed:        d.Allowed,
		Code:           d.Code,
		Reason:         d.Reason,
		IdempotencyKey: action.IdempotencyKey,
		ActorID:        action.ActorID,
		CreatedAt:      g.now(),
	}
	_ = g.store.AppendDecision(out)
	return out
}

func (g *Gateway) isCancelled(id string) bool {
	unlock := g.hold()
	defer unlock()
	return g.cancelled[id]
}

func (g *Gateway) remember(id, state string, d Decision) {
	if id == "" {
		return
	}
	unlock := g.hold()
	defer unlock()
	g.status[id] = Status{ActionID: id, State: state, Decision: d}
}

// CheckDestination authorizes a URL already sitting on a context gateway.
// Callers with no gateway keep their existing behavior.
func CheckDestination(ctx context.Context, actionType, skillID, rawURL string) error {
	if !Required(ctx) && !HasGateway(ctx) {
		return nil
	}
	gw := GatewayFrom(ctx)
	if gw == nil {
		return ErrGatewayRequired
	}
	action, err := HTTPAction(FlowID(ctx), skillID, "GET", rawURL)
	if err != nil {
		return err
	}
	action.ActionType = actionType
	action.SkillID = skillID
	_, err = gw.Authorize(ctx, action)
	return err
}
