package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRAGClient_DisablesAfterConnectionRefused(t *testing.T) {
	hits := 0
	client := NewRAGClient("http://127.0.0.1:8081")
	client.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hits++
			return nil, errors.New("dial tcp 127.0.0.1:8081: connect: connection refused")
		}),
	}

	ctx := context.Background()
	result, err := client.RetrieveKnowledge(ctx, "test query", 3)
	if err != nil {
		t.Fatalf("expected graceful fallback, got error: %v", err)
	}
	if result != "" {
		t.Fatalf("expected empty context when RAG is unavailable, got %q", result)
	}

	result, err = client.RetrieveKnowledge(ctx, "test query", 3)
	if err != nil {
		t.Fatalf("expected disabled client to stay quiet, got error: %v", err)
	}
	if result != "" {
		t.Fatalf("expected empty context on second call, got %q", result)
	}
	if hits != 1 {
		t.Fatalf("expected transport to be hit once before disable, got %d", hits)
	}
}
