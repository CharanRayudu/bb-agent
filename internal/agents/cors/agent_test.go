package cors_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/agents/cors"
	"github.com/bb-agent/mirage/internal/queue"
)

func makeItem(targetURL string) *queue.Item {
	return &queue.Item{
		Payload: map[string]interface{}{
			"target":   targetURL,
			"context":  "test",
			"priority": "medium",
		},
	}
}

func TestCORSAgent_OriginReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := cors.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL+"/api/data"))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one CORS finding when origin is reflected with credentials")
	}
	for _, f := range findings {
		if f.Confidence < 0.7 {
			t.Errorf("finding confidence %.2f < 0.7", f.Confidence)
		}
	}
}

func TestCORSAgent_NullOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := cors.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected finding for null origin + credentials")
	}
}

func TestCORSAgent_CleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := cors.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for clean server, got %d", len(findings))
	}
}
