package base

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/execution"
	"github.com/bb-agent/mirage/internal/policy"
)

func denyGateway(t *testing.T) *execution.Gateway {
	t.Helper()
	auth, err := policy.AuthorizationForTarget("flow-1", "http://example.com", policy.AutonomyL3, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	book := policy.NewBook()
	stored := book.Put(auth)
	return execution.NewGateway(book, execution.NewMemoryStore(), execution.NetResolver{}).WithAuthorization(stored)
}

func TestFuzzClientDoesNotDialWhenGatewayDenies(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()

	ctx := execution.WithRequired(execution.WithGateway(context.Background(), denyGateway(t)))
	result := NewFuzzClient().ProbeGET(ctx, srv.URL, "q", "1")
	if result.Error == nil {
		t.Fatal("expected denial")
	}
	if hit {
		t.Fatal("FuzzClient dialed after denial")
	}
}

func TestProbeGETIsActiveAtL2(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()
	auth, err := policy.AuthorizationForTarget("flow-1", srv.URL, policy.AutonomyL2, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	book := policy.NewBook()
	stored := book.Put(auth)
	gw := execution.NewGateway(book, execution.NewMemoryStore(), execution.NetResolver{}).WithAuthorization(stored)
	ctx := execution.WithGateway(context.Background(), gw)
	result := NewFuzzClient().ProbeGET(ctx, srv.URL+"/?q=1", "q", "1")
	if result.Error == nil || hit {
		t.Fatalf("active GET ran without L2 approval, err=%v hit=%v", result.Error, hit)
	}
	baselineHit := false
	baseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baselineHit = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer baseSrv.Close()
	baseAuth, err := policy.AuthorizationForTarget("flow-2", baseSrv.URL, policy.AutonomyL2, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	baseBook := policy.NewBook()
	baseStored := baseBook.Put(baseAuth)
	baseGW := execution.NewGateway(baseBook, execution.NewMemoryStore(), execution.NetResolver{}).WithAuthorization(baseStored)
	baseCtx := execution.WithFlowID(execution.WithGateway(context.Background(), baseGW), "flow-2")
	if NewFuzzClient().Baseline(baseCtx, baseSrv.URL) == 0 || !baselineHit {
		t.Fatal("passive baseline should still run at L2")
	}
}

func TestBrowserNavigationIsPassiveAndProbesAreActive(t *testing.T) {
	auth, err := policy.AuthorizationForTarget("flow-1", "http://example.com", policy.AutonomyL2, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	book := policy.NewBook()
	stored := book.Put(auth)
	gw := execution.NewGateway(book, execution.NewMemoryStore(), fixedResolver{}).WithAuthorization(stored)
	ctx := execution.WithFlowID(execution.WithGateway(context.Background(), gw), "flow-1")
	opts := DefaultBrowserOptions()
	closeNav, err := PrepareBrowserEgress(ctx, "http://example.com/", &opts)
	if err != nil {
		t.Fatalf("passive navigation was blocked: %v", err)
	}
	closeNav()
	opts.Active = true
	if _, err := PrepareBrowserEgress(ctx, "http://example.com/?q=%3Cscript%3E", &opts); err == nil {
		t.Fatal("active GET probe did not require approval")
	}
}

func TestRunHeadlessPOSTChecksTheFormTarget(t *testing.T) {
	auth, err := policy.AuthorizationForTarget("flow-1", "http://example.com", policy.AutonomyL3, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	book := policy.NewBook()
	stored := book.Put(auth)
	gw := execution.NewGateway(book, execution.NewMemoryStore(), fixedResolver{}).WithAuthorization(stored)
	ctx := execution.WithGateway(context.Background(), gw)
	_, err = RunHeadlessPOST(ctx, "http://evil.example/login", map[string]string{"user": "a"}, DefaultBrowserOptions())
	if err == nil {
		t.Fatal("expected the form action to be denied")
	}
	if strings.Contains(err.Error(), "data:") {
		t.Fatalf("egress check parsed the data URL: %v", err)
	}
}

type fixedResolver struct{}

func (fixedResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

func TestRunCrawlDeniedBeforeBrowserLaunch(t *testing.T) {
	ctx := execution.WithGateway(context.Background(), denyGateway(t))
	_, err := RunCrawl(ctx, "http://127.0.0.1:9/", DefaultBrowserOptions())
	if err == nil {
		t.Fatal("expected browser navigation to be denied")
	}
}
