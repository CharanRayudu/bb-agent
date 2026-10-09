package base

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestRunCrawlDeniedBeforeBrowserLaunch(t *testing.T) {
	ctx := execution.WithGateway(context.Background(), denyGateway(t))
	_, err := RunCrawl(ctx, "http://127.0.0.1:9/", DefaultBrowserOptions())
	if err == nil {
		t.Fatal("expected browser navigation to be denied")
	}
}
