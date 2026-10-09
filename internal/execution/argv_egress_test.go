package execution

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestCommandNameDoesNotAuthorizeAScanner(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	run := func(context.Context) (string, error) {
		calls++
		return "ran", nil
	}
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "execute_command", "orchestrator", []byte(`{"command":"nuclei -u http://example.com"}`), run)
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("shell string named nuclei ran, calls=%d err=%v", calls, err)
	}
	last := gw.Store().Decisions()
	if last[len(last)-1].Code != policy.CodeUnrestrictedShell {
		t.Fatalf("code=%s", last[len(last)-1].Code)
	}
	_, err = gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"bash","args":["-c","nuclei -u http://example.com"]}`), run)
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("bash wrapper ran, calls=%d err=%v", calls, err)
	}
}

func TestSecurityToolArgvPermitsScopedFuzzingAndBlocksExtraHosts(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	run := func(context.Context) (string, error) {
		calls++
		return "ran", nil
	}
	payloads := []string{
		`{"tool":"ffuf","args":["-u","http://example.com/FUZZ","-w","/usr/share/dirb/wordlists/common.txt"]}`,
		`{"tool":"sqlmap","args":["-u","http://example.com/item?id=1' OR '1'='1","--batch"]}`,
		`{"tool":"curl","args":["-s","-H","Authorization: Bearer scoped","http://example.com/api"]}`,
	}
	for _, payload := range payloads {
		out, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(payload), run)
		if err != nil || out != "ran" {
			t.Fatalf("payload %s out=%q err=%v", payload, out, err)
		}
	}
	if calls != len(payloads) {
		t.Fatalf("calls=%d", calls)
	}
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"curl","args":["http://example.com","&&","curl","http://evil.example"]}`), run)
	if !errors.Is(err, ErrDenied) || calls != len(payloads) {
		t.Fatalf("injected host ran, calls=%d err=%v", calls, err)
	}
}

func TestProxyPreservesMethodHeadersAndBody(t *testing.T) {
	var method, authz, contentType, body string
	var deniedHit bool
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		authz = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("proxy credential was forwarded")
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer allowed.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deniedHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer blocked.Close()

	gw, _ := newGW(t, testAuth(policy.AutonomyL3, allowed.URL), "127.0.0.1")
	proxy, err := StartFlowProxy(gw, "flow-1")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse("http://" + proxy.Addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, allowed.URL+"/login", strings.NewReader(`{"user":"ada"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", allowed.URL)
	req.Header.Set("Proxy-Authorization", "Basic cHJveHk6c2VjcmV0")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if method != http.MethodPost || authz != "Bearer secret" || contentType != "application/json" || body != `{"user":"ada"}` {
		t.Fatalf("method=%s auth=%s type=%s body=%s", method, authz, contentType, body)
	}

	deniedReq, _ := http.NewRequest(http.MethodGet, blocked.URL+"/secret", nil)
	deniedResp, err := client.Do(deniedReq)
	if err != nil {
		t.Fatal(err)
	}
	defer deniedResp.Body.Close()
	if deniedResp.StatusCode != http.StatusForbidden || deniedHit {
		t.Fatalf("status=%d hit=%v", deniedResp.StatusCode, deniedHit)
	}
}

func TestFlowEgressAllowsOnlyAuthorizedSockets(t *testing.T) {
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
	target := ln.Addr().String()
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://"+target), "127.0.0.1")
	calls := 0
	targetURL := "http://" + target + "/"
	_, err = gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-p","`+strconv.Itoa(port)+`","`+targetURL+`"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("scoped nmap did not run, calls=%d err=%v", calls, err)
	}
	ctx := WithFlowID(context.Background(), "flow-1")
	conn, err := gw.Egress().DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("permitted dial did not reach the listener")
	}
	_, err = gw.Egress().DialContext(ctx, "tcp", "203.0.113.50:80")
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("unapproved address was dialable: %v", err)
	}
	_, err = gw.Egress().DialContext(WithFlowID(context.Background(), "other-flow"), "tcp", target)
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("another flow reused the permit: %v", err)
	}
}

func TestEngagementBudgetAndParentRevocation(t *testing.T) {
	parent := testAuth(policy.AutonomyL3, "http://example.com")
	parent.ID = "auth:flow-1"
	parent.EngagementID = "eng-1"
	parent.MaxRequests = 1
	book := policy.NewBook()
	book.Put(*parent)
	child := parent.CloneForFlow("flow-2")
	book.Put(child)
	gw := NewGateway(book, NewMemoryStore(), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	run := func(context.Context, Action) (string, error) { return "ran", nil }
	parentAction := httpAct(t, "http://example.com/")
	if _, err := gw.Execute(context.Background(), parentAction, run); err != nil {
		t.Fatal(err)
	}
	childAction := parentAction
	childAction.FlowID = "flow-2"
	childAction.IdempotencyKey = "flow-2:child"
	childAction.Digest = ""
	if _, err := gw.Execute(context.Background(), childAction, run); !errors.Is(err, ErrDenied) {
		t.Fatalf("child ignored the engagement budget: %v", err)
	}

	freshParent := testAuth(policy.AutonomyL3, "http://example.com")
	freshParent.ID = "auth:parent"
	freshParent.EngagementID = "eng-2"
	freshParent.FlowID = "parent-flow"
	freshBook := policy.NewBook()
	freshBook.Put(*freshParent)
	freshChild := freshParent.CloneForFlow("child-flow")
	freshBook.Put(freshChild)
	fresh := NewGateway(freshBook, NewMemoryStore(), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	if !freshBook.Revoke(freshParent.ID, time.Now()) {
		t.Fatal("revoke missed the parent")
	}
	revoked := httpAct(t, "http://example.com/")
	revoked.FlowID = "child-flow"
	revoked.IdempotencyKey = "child:revoked"
	if _, err := fresh.Execute(context.Background(), revoked, run); !errors.Is(err, ErrDenied) {
		t.Fatalf("child survived parent revocation: %v", err)
	}
	last := fresh.Store().Decisions()
	if last[len(last)-1].Code != policy.CodeAuthorizationExpired {
		t.Fatalf("code=%s", last[len(last)-1].Code)
	}
}

func TestProtocolMustMatchTheAuthorizedTarget(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com:443"), "93.184.216.34")
	calls := 0
	run := func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	}
	httpsAction, err := HTTPAction("flow-1", "web", http.MethodGet, "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = gw.Execute(context.Background(), httpsAction, run)
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("https reused an http authorization, calls=%d err=%v", calls, err)
	}
	if gw.Store().Decisions()[len(gw.Store().Decisions())-1].Code != policy.CodeSchemeNotAllowed {
		t.Fatalf("code=%s", gw.Store().Decisions()[len(gw.Store().Decisions())-1].Code)
	}
	tcp := Action{
		FlowID:         "flow-1",
		ActionType:     "net.dial",
		Scheme:         "tcp",
		Host:           "example.com",
		Port:           443,
		Risk:           policy.RiskActive,
		IdempotencyKey: "dial-443",
	}
	if _, err := gw.Execute(context.Background(), tcp, run); err != nil || calls != 1 {
		t.Fatalf("tcp dial to the authorized port was denied, calls=%d err=%v", calls, err)
	}
}

func TestRequestFingerprintAndPhaseGrantDoNotCrossRequests(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	if _, err := gw.GrantPhase("flow-1", "exploitation", "operator", "approved", "phase", time.Hour); err != nil {
		t.Fatal(err)
	}
	first := httpAct(t, "http://example.com/login")
	first.Arguments["method"] = http.MethodPost
	first.Risk = policy.RiskActive
	first.Phase = "exploitation"
	firstHeader := http.Header{"Authorization": []string{"Bearer one"}, "Content-Type": []string{"application/json"}}
	first.Digest = RequestFingerprint(http.MethodPost, "http://example.com/login", firstHeader, []byte(`{"n":1}`))
	first.IdempotencyKey += ":" + first.Digest
	second := first
	secondHeader := http.Header{"Authorization": []string{"Bearer two"}, "Content-Type": []string{"application/json"}}
	second.Digest = RequestFingerprint(http.MethodPost, "http://example.com/login", secondHeader, []byte(`{"n":2}`))
	second.IdempotencyKey = httpAct(t, "http://example.com/login").IdempotencyKey + ":" + second.Digest
	calls := 0
	run := func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	}
	if _, err := gw.Execute(context.Background(), first, run); !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("phase grant authorized a POST, calls=%d err=%v", calls, err)
	}
	pending := gw.Store().ApprovalsForFlow("flow-1")
	var id string
	for _, approval := range pending {
		if approval.ActionKey == first.IdempotencyKey && approval.Status == "pending" {
			id = approval.ID
		}
	}
	if id == "" {
		t.Fatal("expected a request-specific pending approval")
	}
	if _, err := gw.ResolveApproval(id, "operator", "approved", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Execute(context.Background(), first, run); err != nil || calls != 1 {
		t.Fatalf("approved request did not run, calls=%d err=%v", calls, err)
	}
	if _, err := gw.Execute(context.Background(), second, run); !errors.Is(err, ErrDenied) || calls != 1 {
		t.Fatalf("different authorization header reused the approval, calls=%d err=%v", calls, err)
	}
}

func TestTerminalApprovalTransitions(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL1, "http://example.com"), "93.184.216.34")
	action := httpAct(t, "http://example.com/a")
	if _, err := gw.Execute(context.Background(), action, nil); err == nil {
		t.Fatal("expected pending")
	}
	pending := gw.Store().ApprovalsForFlow("flow-1")
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "ok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "denied", "no", 0); err == nil {
		t.Fatal("approved request was denied")
	}
	if _, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		return "ran", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.ResolveApproval(pending[0].ID, "operator", "approved", "again", time.Hour); err == nil {
		t.Fatal("consumed approval was approved again")
	}
	other := httpAct(t, "http://example.com/b")
	if _, err := gw.Execute(context.Background(), other, nil); err == nil {
		t.Fatal("expected a second pending approval")
	}
	var otherID string
	for _, approval := range gw.Store().ApprovalsForFlow("flow-1") {
		if approval.ActionKey == other.IdempotencyKey && approval.Status == "pending" {
			otherID = approval.ID
		}
	}
	if _, err := gw.ResolveApproval(otherID, "operator", "expired", "too late", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.ResolveApproval(otherID, "operator", "approved", "late", time.Hour); err == nil {
		t.Fatal("expired approval was approved")
	}
}

func TestAppendProxyArgLeavesRawSocketToolsAlone(t *testing.T) {
	proxied := AppendProxyArg([]string{"curl", "-s", "http://example.com"}, "http://127.0.0.1:9")
	if strings.Join(proxied, " ") != "curl --proxy http://127.0.0.1:9 -s http://example.com" {
		t.Fatalf("curl argv=%v", proxied)
	}
	raw := AppendProxyArg([]string{"nmap", "-p", "80", "example.com"}, "http://127.0.0.1:9")
	if strings.Join(raw, " ") != "nmap -p 80 example.com" {
		t.Fatalf("nmap argv=%v", raw)
	}
}
