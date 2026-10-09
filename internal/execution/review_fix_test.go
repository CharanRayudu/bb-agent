package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestApprovalResumeReleasesTheWaitingAction(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL2, "http://example.com"), "93.184.216.34")
	gw.EnableResume()
	action := httpAct(t, "http://example.com/probe")
	action = action.WithRisk(policy.RiskActive)
	calls := 0
	done := make(chan error, 1)
	go func() {
		_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
			calls++
			return "ok", nil
		})
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	var pending []policy.Approval
	for time.Now().Before(deadline) {
		pending = gw.Store().(*MemoryStore).allLocked()
		if len(pending) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) == 0 {
		t.Fatal("operator was not shown a pending approval")
	}
	if pending[0].Status != "pending" {
		t.Fatalf("status=%s", pending[0].Status)
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "resume", time.Hour); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil || calls != 1 {
			t.Fatalf("resume did not run the action, calls=%d err=%v", calls, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval did not resume the action")
	}
}

func TestNucleiStaysAvailableInsideScope(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	out, err := gw.ExecuteTool(context.Background(), "flow-1", "execute_command", "orchestrator", []byte(`{"command":"nuclei -u http://example.com"}`), func(context.Context) (string, error) {
		calls++
		return "template-match", nil
	})
	if err != nil || out != "template-match" || calls != 1 {
		t.Fatalf("scoped nuclei should run, out=%q calls=%d err=%v", out, calls, err)
	}
}

func TestSecondDestinationBlocksTheWholeCommand(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "execute_command", "orchestrator", []byte(`{"command":"curl http://example.com http://evil.example"}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("mixed command ran, calls=%d err=%v", calls, err)
	}
}

func TestArbitraryShellStaysDeniedAfterPhaseApproval(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	if _, err := gw.GrantPhase("flow-1", "exploitation", "operator", "approved", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "execute_command", "orchestrator", []byte(`{"command":"bash -c id"}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("shell ran after phase approval, calls=%d err=%v", calls, err)
	}
	last := gw.Store().Decisions()
	if last[len(last)-1].Code != policy.CodeUnrestrictedShell {
		t.Fatalf("code=%s", last[len(last)-1].Code)
	}
}

func TestPublicDNSChangeIsRebinding(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	book := policy.NewBook()
	stored := book.Put(*auth)
	resolver := &scriptResolver{seq: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}}
	gw := NewGateway(book, NewMemoryStore(), resolver).WithAuthorization(stored)
	calls := 0
	_, err := gw.Execute(context.Background(), httpAct(t, "http://example.com/"), func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("rebinding executed, calls=%d err=%v", calls, err)
	}
	last := gw.Store().Decisions()
	if last[len(last)-1].Code != policy.CodeDNSRebinding {
		t.Fatalf("code=%s reason=%s", last[len(last)-1].Code, last[len(last)-1].Reason)
	}
}

func TestPinnedDialUsesAuthorizedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	conn, err := dialPinned(context.Background(), "tcp", fmt.Sprintf("example.com:%d", port), []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("pinned dial did not use the authorized address")
	}
}

func TestDeniedApprovalCannotBeApproved(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/a")
	_, _ = gw.Execute(context.Background(), action, nil)
	pending := gw.Store().(*MemoryStore).approvals
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "denied", "no", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "changed my mind", time.Hour); err == nil {
		t.Fatal("denied approval was approved by a later update")
	}
}

func TestDifferentPayloadsDoNotShareApproval(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	first := httpAct(t, "http://example.com/login")
	first.Digest = Digest("user=a")
	first.IdempotencyKey += ":" + first.Digest
	second := httpAct(t, "http://example.com/login")
	second.Digest = Digest("user=b")
	second.IdempotencyKey += ":" + second.Digest
	_, _ = gw.Execute(context.Background(), first, nil)
	pending := gw.Store().(*MemoryStore).approvals
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := gw.Execute(context.Background(), second, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("second payload reused the first approval, calls=%d err=%v", calls, err)
	}
}

func TestAuditFailureBlocksRelease(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	book := policy.NewBook()
	stored := book.Put(*auth)
	gw := NewGateway(book, failStore{}, &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}}).WithAuthorization(stored)
	calls := 0
	_, err := gw.Execute(context.Background(), httpAct(t, "http://example.com/"), func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrAudit) || calls != 0 {
		t.Fatalf("action ran without an audit record, calls=%d err=%v", calls, err)
	}
}

type failStore struct{}

func (failStore) AppendDecision(Decision) error                { return errors.New("disk full") }
func (failStore) Decisions() []Decision                        { return nil }
func (failStore) SaveApproval(policy.Approval) error           { return errors.New("disk full") }
func (failStore) ApprovalsForFlow(string) []policy.Approval    { return nil }
func (failStore) SaveAuthorization(policy.Authorization) error { return errors.New("disk full") }

func TestRestartRestoresPendingApprovalAndScope(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://lab.internal"), "127.0.0.1")
	action := httpAct(t, "http://lab.internal/")
	_, _ = gw.Execute(context.Background(), action, nil)
	snap := gw.Export()
	restored := NewGateway(policy.NewBook(), NewMemoryStore(), &scriptResolver{seq: []net.IP{net.ParseIP("127.0.0.1")}})
	Restore(restored, snap)
	calls := 0
	_, err := restored.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("restored engagement lost its pending approval, calls=%d err=%v", calls, err)
	}
	other := httpAct(t, "http://evil.example/")
	_, err = restored.Execute(context.Background(), other, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("restored scope allowed another host, calls=%d err=%v", calls, err)
	}
}

func TestIdempotentCompletionDoesNotRunTwice(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/once")
	calls := 0
	run := func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	}
	if _, err := gw.Execute(context.Background(), action, run); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Execute(context.Background(), action, run); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("completed action ran %d times", calls)
	}
}

func TestProxyRefusesOutOfScopeSubresource(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	proxy := &EgressProxy{gw: gw}
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/app.js", nil)
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("status=%d body=%s", rr.Code, body)
	}
	if strings.Contains(rr.Body.String(), "template-match") {
		t.Fatal("unexpected success body")
	}
}

func TestCloneKeepsParentRestrictions(t *testing.T) {
	parent := testAuth(policy.AutonomyL2, "http://example.com")
	parent.ExpiresAt = time.Now().Add(time.Minute)
	parent.ProhibitedActions = []string{"tool.nmap"}
	clone := parent.CloneForFlow("child-flow")
	if clone.Autonomy != policy.AutonomyL2 {
		t.Fatalf("autonomy elevated to %s", clone.Autonomy)
	}
	if !clone.ExpiresAt.Equal(parent.ExpiresAt) {
		t.Fatal("clone extended the parent window")
	}
	if len(clone.ProhibitedActions) != 1 || clone.ProhibitedActions[0] != "tool.nmap" {
		t.Fatalf("prohibited actions changed: %+v", clone.ProhibitedActions)
	}
	if clone.FlowID != "child-flow" || clone.EngagementID != parent.FlowID && clone.EngagementID != parent.EngagementID {
		t.Fatalf("lineage lost: %+v", clone)
	}
}

func TestExplicitIPv6LabTarget(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://[::1]:8080")
	book := policy.NewBook()
	stored := book.Put(*auth)
	gw := NewGateway(book, NewMemoryStore(), NetResolver{}).WithAuthorization(stored)
	action := httpAct(t, "http://[::1]:8080/health")
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("explicit IPv6 lab target was blocked, calls=%d err=%v", calls, err)
	}
}

func TestSubdomainExclusionWins(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	auth.AllowSubdomains = true
	auth.Exclusions = []policy.Target{{Scheme: "http", Host: "api.example.com", Port: 80}}
	book := policy.NewBook()
	stored := book.Put(*auth)
	gw := NewGateway(book, NewMemoryStore(), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}}).WithAuthorization(stored)
	allowed := httpAct(t, "http://www.example.com/")
	calls := 0
	if _, err := gw.Execute(context.Background(), allowed, func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	}); err != nil || calls != 1 {
		t.Fatalf("wildcard host should be allowed, calls=%d err=%v", calls, err)
	}
	blocked := httpAct(t, "http://api.example.com/")
	if _, err := gw.Execute(context.Background(), blocked, func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	}); err == nil || calls != 1 {
		t.Fatalf("excluded subdomain was contacted, calls=%d err=%v", calls, err)
	}
}
