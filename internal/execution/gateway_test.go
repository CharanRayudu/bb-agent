package execution

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

type scriptResolver struct {
	seq []net.IP
	i   int
}

func (s *scriptResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if len(s.seq) == 0 {
		return nil, errors.New("no scripted addresses")
	}
	if s.i >= len(s.seq) {
		return []net.IP{s.seq[len(s.seq)-1]}, nil
	}
	ip := s.seq[s.i]
	s.i++
	return []net.IP{ip}, nil
}

func testAuth(level policy.Autonomy, raw string) *policy.Authorization {
	target, err := policy.ParseTarget(raw)
	if err != nil {
		panic(err)
	}
	auth := &policy.Authorization{
		ID:        "auth-test",
		FlowID:    "flow-1",
		Owner:     "tester",
		Autonomy:  level,
		Targets:   []policy.Target{target},
		NotBefore: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	return auth
}

func newGW(t *testing.T, auth *policy.Authorization, ips ...string) (*Gateway, *scriptResolver) {
	t.Helper()
	book := policy.NewBook()
	var stored *policy.Authorization
	if auth != nil {
		stored = book.Put(*auth)
	}
	parsed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsed = append(parsed, net.ParseIP(ip))
	}
	if len(parsed) == 0 {
		parsed = []net.IP{net.ParseIP("93.184.216.34")}
	}
	resolver := &scriptResolver{seq: parsed}
	store := NewMemoryStore()
	gw := NewGateway(book, store, resolver).WithAuthorization(stored)
	return gw, resolver
}

func httpAct(t *testing.T, raw string) Action {
	t.Helper()
	action, err := HTTPAction("flow-1", "web.headers.audit", http.MethodGet, raw)
	if err != nil {
		t.Fatal(err)
	}
	action.FollowRedirects = false
	return action
}

func TestL1BlocksUntilApproval(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/health")
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("expected denial before approval, calls=%d err=%v", calls, err)
	}
	pending := gw.Store().(*MemoryStore).approvals
	if len(pending) == 0 {
		t.Fatal("expected a durable pending approval")
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("approved L1 action should run once, calls=%d err=%v", calls, err)
	}
}

func TestL2ExploitationRequiresApproval(t *testing.T) {
	auth := testAuth(policy.AutonomyL2, "http://example.com")
	gw, _ := newGW(t, auth, "93.184.216.34")
	calls := 0
	run := func(context.Context) (string, error) {
		calls++
		return "ran", nil
	}
	payload := []byte(`{"tool":"nuclei","args":["-u","http://example.com/"]}`)
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", payload, run)
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("L2 shell ran before approval: calls=%d err=%v", calls, err)
	}
	pending := gw.Store().(*MemoryStore).approvals
	if len(pending) == 0 {
		t.Fatal("expected pending approval")
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "proceed", time.Hour); err != nil {
		t.Fatal(err)
	}
	out, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", payload, run)
	if err != nil || out != "ran" || calls != 1 {
		t.Fatalf("approved L2 shell should run, out=%q calls=%d err=%v", out, calls, err)
	}
}

func TestDeniedApprovalStaysDeniedOnRetry(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/")
	calls := 0
	run := func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	}
	_, _ = gw.Execute(context.Background(), action, run)
	pending := gw.Store().(*MemoryStore).approvals
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "denied", "no", 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, err := gw.Execute(context.Background(), action, run)
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if calls != 0 {
		t.Fatalf("denied approval reached transport %d times", calls)
	}
	last := gw.Store().Decisions()
	if got := last[len(last)-1].Code; got != policy.CodeApprovalDenied {
		t.Fatalf("last code = %s", got)
	}
}

func TestExpiredApprovalBlocksExecution(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	now := time.Now()
	gw.SetClock(func() time.Time { return now })
	action := httpAct(t, "http://example.com/")
	_, _ = gw.Execute(context.Background(), action, nil)
	pending := gw.Store().(*MemoryStore).approvals
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "ok", time.Minute); err != nil {
		t.Fatal(err)
	}
	gw.SetClock(func() time.Time { return now.Add(2 * time.Minute) })
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("expired approval executed: calls=%d err=%v", calls, err)
	}
	decisions := gw.Store().Decisions()
	if decisions[len(decisions)-1].Code != policy.CodeApprovalExpired {
		t.Fatalf("code = %s", decisions[len(decisions)-1].Code)
	}
}

func TestOutOfScopeHostPortAndResolvedIP(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	cases := []struct {
		name string
		url  string
		ips  []string
		code string
	}{
		{"host", "http://evil.example/", []string{"93.184.216.34"}, policy.CodeOutOfScope},
		{"port", "http://example.com:22/", []string{"93.184.216.34"}, policy.CodePortNotAuthorized},
		{"private", "http://example.com/", []string{"10.1.2.3"}, policy.CodePrivateAddress},
		{"metadata", "http://example.com/", []string{"169.254.169.254"}, policy.CodeMetadataAddress},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			local, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), tc.ips...)
			action := httpAct(t, tc.url)
			calls := 0
			_, err := local.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
				calls++
				return "ran", nil
			})
			if !errors.Is(err, ErrDenied) || calls != 0 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			got := local.Store().Decisions()
			if got[len(got)-1].Code != tc.code {
				t.Fatalf("code=%s want %s (%s)", got[len(got)-1].Code, tc.code, got[len(got)-1].Reason)
			}
		})
	}
	_ = gw
}

func TestDNSRebindingBlockedBeforeTransport(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	book := policy.NewBook()
	stored := book.Put(*auth)
	resolver := &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.9.8.7")}}
	gw := NewGateway(book, NewMemoryStore(), resolver).WithAuthorization(stored)
	action := tAction("http://example.com/")
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("rebinding reached transport calls=%d err=%v", calls, err)
	}
	if got := gw.Store().Decisions(); got[len(got)-1].Code != policy.CodePrivateAddress {
		t.Fatalf("code=%s", got[len(got)-1].Code)
	}
}

func tAction(raw string) Action {
	action, err := HTTPAction("flow-1", "web.headers.audit", http.MethodGet, raw)
	if err != nil {
		panic(err)
	}
	action.FollowRedirects = false
	return action
}

func TestRedirectIsAuthorizedBeforeFollow(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/start")
	action.FollowRedirects = true
	trips := 0
	gw.SetRoundTrip(func(req *http.Request, ips []net.IP) (*http.Response, error) {
		if len(ips) == 0 {
			t.Fatal("redirect hop had no pinned addresses")
		}
		trips++
		if trips > 1 {
			t.Fatal("transport was called for the redirected host")
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://evil.example/admin"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	_, err := gw.FollowRedirect(context.Background(), action, nil)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("redirect err=%v", err)
	}
	if trips != 1 {
		t.Fatalf("trips=%d", trips)
	}
}

func TestUnrestrictedShellDeniedForAutonomousFlow(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "execute_command", "orchestrator", []byte(`{"command":"bash -c id"}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("shell executed: calls=%d err=%v", calls, err)
	}
	last := gw.Store().Decisions()
	if last[len(last)-1].Code != policy.CodeUnrestrictedShell {
		t.Fatalf("code=%s", last[len(last)-1].Code)
	}
}

func TestExplicitLocalTargetAllowed(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://127.0.0.1:8080"))
	action := httpAct(t, "http://127.0.0.1:8080/health")
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("explicit loopback should be allowed, calls=%d err=%v", calls, err)
	}
}

func TestSubdomainIsNotImplicitlyAuthorized(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://api.example.com/")
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ok", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("subdomain was allowed: calls=%d err=%v", calls, err)
	}
}

func TestCancelPreventsExecution(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/")
	action.ID = "act-1"
	if err := gw.Cancel(context.Background(), action.ID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrCancelled) || calls != 0 {
		t.Fatalf("cancelled action ran: calls=%d err=%v", calls, err)
	}
	st, err := gw.GetStatus(context.Background(), action.ID)
	if err != nil || st.State != "cancelled" {
		t.Fatalf("status=%+v err=%v", st, err)
	}
}
