package k8s_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	k8sagent "github.com/bb-agent/mirage/internal/agents/k8s"
	"github.com/bb-agent/mirage/internal/queue"
)

func makeItem(targetURL string) *queue.Item {
	return &queue.Item{
		Payload: map[string]interface{}{
			"target":   targetURL,
			"priority": "critical",
		},
	}
}

func TestK8sAgent_ExposedAPIServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces":
			w.Header().Set("Content-Type", "application/json")
			// Must contain the exact jsonIndicator the agent looks for.
			w.Write([]byte(`{"kind":"NamespaceList","items":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := k8sagent.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected finding for exposed K8s API server")
	}
}

func TestK8sAgent_ExposedDockerAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		case "/v1.40/containers/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Must contain the jsonIndicator: `"Id"`
			w.Write([]byte(`[{"Id":"abc123","Image":"nginx"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := k8sagent.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected finding for exposed Docker API")
	}
}

func TestK8sAgent_AllProtected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := k8sagent.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for 401 responses, got %d", len(findings))
	}
}
