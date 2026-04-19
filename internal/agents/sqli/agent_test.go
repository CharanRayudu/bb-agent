package sqli_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/agents/sqli"
	"github.com/bb-agent/mirage/internal/queue"
)

func makeItem(targetURL, ctx, priority string) *queue.Item {
	return &queue.Item{
		Payload: map[string]interface{}{
			"target":   targetURL,
			"context":  ctx,
			"priority": priority,
		},
	}
}

func TestSQLiAgent_ErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("inject")
		if strings.Contains(param, "'") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("normal response"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a := sqli.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL+"?inject=1", "", "high"))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one SQLi finding for error-based injection")
	}
	for _, f := range findings {
		if f.Confidence < 0.7 {
			t.Errorf("error-based finding confidence %.2f < 0.7", f.Confidence)
		}
	}
}

func TestSQLiAgent_BooleanBlind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("inject")
		// True condition → long response; false condition → short response
		if strings.Contains(param, "1=1") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Repeat("A", 200)))
			return
		}
		if strings.Contains(param, "1=2") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("x"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("base"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a := sqli.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL+"?inject=1", "boolean condition", "high"))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected boolean-blind SQLi finding for differential response")
	}
}

func TestSQLiAgent_Clean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("everything is fine"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a := sqli.New()
	findings, err := a.ProcessItem(ctx, makeItem(srv.URL+"?id=1", "", "medium"))
	if err != nil {
		t.Fatalf("ProcessItem error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for clean server, got %d", len(findings))
	}
}
