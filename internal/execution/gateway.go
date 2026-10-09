package execution

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
	"github.com/google/uuid"
)

var (
	ErrDenied          = errors.New("action denied")
	ErrGatewayRequired = errors.New("execution gateway required")
	ErrCancelled       = errors.New("action cancelled")
	ErrAudit           = errors.New("audit persistence failed")
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
	completed map[string]Result
	lock      chan struct{}
	resume    bool
	waiters   map[string][]chan struct{}
	roundTrip func(*http.Request, []net.IP) (*http.Response, error)
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
		completed: map[string]Result{},
		lock:      make(chan struct{}, 1),
		waiters:   map[string][]chan struct{}{},
	}
}

// EnableResume blocks approval-required actions until an operator resolves them.
func (g *Gateway) EnableResume() {
	if g != nil {
		g.resume = true
	}
}

// SetRoundTrip replaces the pinned dialer. Tests use it to observe authorized IPs
// without opening a socket. Production leaves this unset.
func (g *Gateway) SetRoundTrip(fn func(*http.Request, []net.IP) (*http.Response, error)) {
	if g != nil {
		g.roundTrip = fn
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
	decision, _, err := g.decide(ctx, action, true)
	return decision, err
}

func (g *Gateway) decide(ctx context.Context, action Action, wait bool) (Decision, []net.IP, error) {
	decision, ips, err := g.authorizeOnce(ctx, action)
	if wait && g != nil && g.resume && decision.Code == policy.CodeApprovalRequired {
		return g.waitForDecision(ctx, action)
	}
	return decision, ips, err
}

func (g *Gateway) authorizeOnce(ctx context.Context, action Action) (Decision, []net.IP, error) {
	if g == nil {
		return Decision{}, nil, ErrGatewayRequired
	}
	action = g.prepare(action)
	if g.isCancelled(action.ID) {
		d, err := g.persist(action, policy.Decision{Allowed: false, Code: "cancelled", Reason: "action was cancelled"})
		if err != nil {
			return d, nil, err
		}
		g.remember(action.ID, "cancelled", d)
		return d, nil, ErrCancelled
	}
	first, firstIPs, err := g.evaluate(ctx, action)
	if err != nil {
		d, perr := g.persist(action, policy.Decision{Allowed: false, Code: policy.CodeAuditFailed, Reason: err.Error()})
		if perr != nil {
			return d, nil, fmt.Errorf("%w: %v", ErrAudit, perr)
		}
		g.remember(action.ID, "audit_failed", d)
		return d, nil, fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if !first.Allowed {
		d, err := g.persist(action, first)
		if err != nil {
			return d, nil, err
		}
		g.remember(action.ID, decisionState(first), d)
		return d, nil, denial(d)
	}
	second, secondIPs, err := g.evaluate(ctx, action)
	if err != nil {
		d, perr := g.persist(action, policy.Decision{Allowed: false, Code: policy.CodeAuditFailed, Reason: err.Error()})
		if perr != nil {
			return d, nil, fmt.Errorf("%w: %v", ErrAudit, perr)
		}
		g.remember(action.ID, "audit_failed", d)
		return d, nil, fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if first.Allowed && second.Allowed && !sameIPSet(firstIPs, secondIPs) {
		second = policy.Decision{Allowed: false, Code: policy.CodeDNSRebinding, Reason: "dns answer changed between authorization checks"}
		secondIPs = nil
	}
	if !second.Allowed {
		d, err := g.persist(action, second)
		if err != nil {
			return d, nil, err
		}
		g.remember(action.ID, decisionState(second), d)
		return d, nil, denial(d)
	}
	for _, extra := range action.ExtraTargets {
		extraAction, err := HTTPAction(action.FlowID, action.SkillID, "GET", extra)
		if err != nil {
			d, perr := g.persist(action, policy.Decision{Allowed: false, Code: policy.CodeInvalidTarget, Reason: err.Error()})
			if perr != nil {
				return d, nil, perr
			}
			g.remember(action.ID, "denied", d)
			return d, nil, denial(d)
		}
		extraAction.Risk = action.Risk
		extraAction.Phase = action.Phase
		verdict, _, err := g.evaluate(ctx, extraAction)
		if err != nil {
			return Decision{}, nil, fmt.Errorf("%w: %v", ErrAudit, err)
		}
		if !verdict.Allowed {
			d, perr := g.persist(action, verdict)
			if perr != nil {
				return d, nil, perr
			}
			g.remember(action.ID, decisionState(verdict), d)
			return d, nil, denial(d)
		}
	}
	if !g.consume(action.FlowID) {
		denied := policy.Decision{Allowed: false, Code: policy.CodeBudgetExhausted, Reason: "request budget for this authorization is exhausted"}
		d, err := g.persist(action, denied)
		if err != nil {
			return d, nil, err
		}
		g.remember(action.ID, "denied", d)
		return d, nil, denial(d)
	}
	d, err := g.persist(action, second)
	if err != nil {
		return d, nil, err
	}
	g.remember(action.ID, "authorized", d)
	return d, parseIPs(secondIPs), nil
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
	action = g.prepare(action)
	if cached, ok := g.cachedResult(action.IdempotencyKey); ok {
		return cached, nil
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
	} else {
		g.rememberCompleted(action.IdempotencyKey, Result{Decision: decision, Output: output})
		_ = g.consumeApproval(action)
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
	g.notify(approval.ID, approval.FlowID, approval.Phase)
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
	if current.Status == "denied" || current.Status == "consumed" || current.Status == "expired" {
		if status == "approved" {
			return policy.Approval{}, fmt.Errorf("approval %s is %s and cannot become approved", id, current.Status)
		}
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
	g.notify(current.ID, current.FlowID, current.Phase)
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

func (g *Gateway) evaluate(ctx context.Context, action Action) (policy.Decision, []string, error) {
	auth := g.auth
	if action.FlowID != "" {
		if snap, ok := g.book.Snapshot(action.FlowID); ok {
			auth = &snap
		}
	}
	ips, err := g.resolve(ctx, action)
	if err != nil {
		return policy.Decision{Allowed: false, Code: "dns_failed", Reason: err.Error()}, nil, nil
	}
	var approval *policy.Approval
	if match, ok := g.matchApproval(action); ok {
		approval = &match
	}
	decision := g.engine.Decide(auth, action.subject(ips), approval, g.now())
	if decision.Code == policy.CodeApprovalRequired {
		if _, err := g.ensurePending(action); err != nil {
			return policy.Decision{}, nil, err
		}
	}
	return decision, ips, nil
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
	var actionHit *policy.Approval
	var phaseHit *policy.Approval
	for _, approval := range g.store.ApprovalsForFlow(action.FlowID) {
		if approval.ActionKey != "" && approval.ActionKey == action.IdempotencyKey {
			cp := approval
			actionHit = &cp
		}
		if approval.ActionKey == "" && approval.Phase != "" && approval.Phase == action.Phase {
			cp := approval
			phaseHit = &cp
		}
	}
	if actionHit != nil && (actionHit.Status == "denied" || actionHit.Status == "approved") {
		return *actionHit, true
	}
	if phaseHit != nil && (phaseHit.Status == "approved" || phaseHit.Status == "denied") {
		return *phaseHit, true
	}
	if actionHit != nil {
		return *actionHit, true
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
		ID:         uuid.NewString(),
		FlowID:     action.FlowID,
		ActionKey:  action.IdempotencyKey,
		Phase:      action.Phase,
		Status:     "pending",
		Reason:     "waiting for operator approval",
		Method:     methodOf(action),
		Target:     urlOf(action),
		Digest:     action.Digest,
		Risk:       string(action.Risk),
		Capability: action.SkillID,
		CreatedAt:  g.now(),
	}
	if err := g.store.SaveApproval(approval); err != nil {
		return policy.Approval{}, err
	}
	return approval, nil
}

func (g *Gateway) persist(action Action, d policy.Decision) (Decision, error) {
	out := Decision{
		ID:             uuid.NewString(),
		ActionID:       action.ID,
		FlowID:         action.FlowID,
		Allowed:        false,
		Code:           policy.CodeAuditFailed,
		Reason:         "audit record was not stored",
		IdempotencyKey: action.IdempotencyKey,
		ActorID:        action.ActorID,
		CreatedAt:      g.now(),
	}
	recorded := Decision{
		ID:             out.ID,
		ActionID:       action.ID,
		FlowID:         action.FlowID,
		Allowed:        d.Allowed,
		Code:           d.Code,
		Reason:         d.Reason,
		IdempotencyKey: action.IdempotencyKey,
		ActorID:        action.ActorID,
		CreatedAt:      out.CreatedAt,
	}
	if g.store == nil {
		return out, ErrAudit
	}
	if err := g.store.AppendDecision(recorded); err != nil {
		out.Reason = err.Error()
		return out, fmt.Errorf("%w: %v", ErrAudit, err)
	}
	return recorded, nil
}

func (g *Gateway) isCancelled(id string) bool {
	unlock := g.hold()
	defer unlock()
	return g.cancelled[id]
}

func (g *Gateway) cachedResult(key string) (Result, bool) {
	if g == nil || key == "" {
		return Result{}, false
	}
	unlock := g.hold()
	defer unlock()
	result, ok := g.completed[key]
	return result, ok
}

func (g *Gateway) rememberCompleted(key string, result Result) {
	if g == nil || key == "" {
		return
	}
	unlock := g.hold()
	defer unlock()
	if g.completed == nil {
		g.completed = map[string]Result{}
	}
	g.completed[key] = result
}

func (g *Gateway) consumeApproval(action Action) error {
	approval, ok := g.matchApproval(action)
	if !ok || approval.ActionKey == "" || approval.Status != "approved" {
		return nil
	}
	approval.Status = "consumed"
	approval.Reason = "action completed"
	return g.store.SaveApproval(approval)
}

func (g *Gateway) remember(id, state string, d Decision) {
	if id == "" {
		return
	}
	unlock := g.hold()
	defer unlock()
	g.status[id] = Status{ActionID: id, State: state, Decision: d}
}

func (g *Gateway) waitForDecision(ctx context.Context, action Action) (Decision, []net.IP, error) {
	for {
		pending, ok := g.matchApproval(action)
		ch := make(chan struct{}, 1)
		if ok {
			g.addWaiter(pending.ID, action.FlowID, action.Phase, ch)
		}
		var timer <-chan time.Time
		if ok && !pending.ExpiresAt.IsZero() {
			delay := pending.ExpiresAt.Sub(g.now())
			if delay < 0 {
				delay = 0
			}
			timer = time.After(delay)
		}
		select {
		case <-ctx.Done():
			d, err := g.persist(action, policy.Decision{Allowed: false, Code: "cancelled", Reason: "approval wait cancelled"})
			if err != nil {
				return d, nil, err
			}
			g.remember(action.ID, "cancelled", d)
			return d, nil, ErrCancelled
		case <-ch:
		case <-timer:
		}
		decision, ips, err := g.authorizeOnce(ctx, action)
		if decision.Code != policy.CodeApprovalRequired {
			return decision, ips, err
		}
	}
}

func (g *Gateway) addWaiter(approvalID, flowID, phase string, ch chan struct{}) {
	unlock := g.hold()
	defer unlock()
	if g.waiters == nil {
		g.waiters = map[string][]chan struct{}{}
	}
	if approvalID != "" {
		g.waiters[approvalID] = append(g.waiters[approvalID], ch)
	}
	g.waiters["phase:"+flowID+":"+phase] = append(g.waiters["phase:"+flowID+":"+phase], ch)
}

func (g *Gateway) notify(approvalID, flowID, phase string) {
	if g == nil {
		return
	}
	unlock := g.hold()
	defer unlock()
	wake(g.waiters[approvalID])
	wake(g.waiters["phase:"+flowID+":"+phase])
}

func wake(waiters []chan struct{}) {
	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func decisionState(d policy.Decision) string {
	if d.Allowed {
		return "authorized"
	}
	switch d.Code {
	case policy.CodeApprovalRequired:
		return "waiting_approval"
	case policy.CodeApprovalExpired:
		return "expired"
	case "cancelled":
		return "cancelled"
	case policy.CodeAuditFailed:
		return "audit_failed"
	default:
		return "denied"
	}
}

func denial(d Decision) error {
	return &denialError{Decision: d}
}

type denialError struct {
	Decision Decision
}

func (e *denialError) Error() string {
	if e.Decision.Reason != "" {
		return e.Decision.Reason
	}
	return ErrDenied.Error()
}

func (e *denialError) Unwrap() error {
	switch e.Decision.Code {
	case "cancelled":
		return ErrCancelled
	case policy.CodeAuditFailed:
		return ErrAudit
	default:
		return ErrDenied
	}
}

func sameIPSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func parseIPs(values []string) []net.IP {
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			out = append(out, ip)
		}
	}
	return out
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
