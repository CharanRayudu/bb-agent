package llm

import (
	"context"
	"errors"
	"testing"
)

type countingStub struct {
	calls int
	err   error
}

func (c *countingStub) Name() string { return "stub" }

func (c *countingStub) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	c.calls++
	return nil, c.err
}

func TestGuardedProviderStopsRepeatingPermanentFailures(t *testing.T) {
	stub := &countingStub{err: errors.New(`The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account.`)}
	guard := NewGuardedProvider(stub, Selection{Model: "gpt-5.3-codex", Source: "codex_oauth"})
	if _, err := guard.Complete(context.Background(), CompletionRequest{}); err == nil {
		t.Fatal("expected permanent failure")
	}
	if _, err := guard.Complete(context.Background(), CompletionRequest{}); err == nil {
		t.Fatal("expected blocked failure")
	}
	if stub.calls != 1 {
		t.Fatalf("calls=%d want 1", stub.calls)
	}
}
