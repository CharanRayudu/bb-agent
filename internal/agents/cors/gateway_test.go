package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/execution"
	"github.com/bb-agent/mirage/internal/policy"
	"github.com/bb-agent/mirage/internal/queue"
)

func TestCORSAgentCannotBypassGateway(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	auth, err := policy.AuthorizationForTarget("flow-1", "http://example.com", policy.AutonomyL3, "tester", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	book := policy.NewBook()
	stored := book.Put(auth)
	gw := execution.NewGateway(book, execution.NewMemoryStore(), execution.NetResolver{}).WithAuthorization(stored)
	ctx := execution.WithRequired(execution.WithGateway(context.Background(), gw))

	_, err = New().ProcessItem(ctx, &queue.Item{Payload: map[string]interface{}{
		"target":   srv.URL + "/api/data",
		"_flow_id": "flow-1",
	}})
	if err == nil {
		t.Fatal("expected the gateway to deny the probe")
	}
	if hit {
		t.Fatal("CORS client sent a request after the gateway denied it")
	}
	decisions := gw.Store().Decisions()
	if len(decisions) == 0 || decisions[len(decisions)-1].Allowed {
		t.Fatalf("expected a durable denial, got %+v", decisions)
	}
}
