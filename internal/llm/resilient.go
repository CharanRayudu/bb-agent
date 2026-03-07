package llm

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// ResilientProvider wraps an existing Provider with retry logic and backoff
type ResilientProvider struct {
	base       Provider
	maxRetries int
	baseDelay  time.Duration
}

// NewResilientProvider creates a new resilient wrapper
func NewResilientProvider(base Provider) *ResilientProvider {
	return &ResilientProvider{
		base:       base,
		maxRetries: 3,
		baseDelay:  2 * time.Second,
	}
}

func (r *ResilientProvider) Name() string {
	return fmt.Sprintf("%s (resilient)", r.base.Name())
}

// Complete executes an LLM completion with exponential backoff retries
func (r *ResilientProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := r.base.Complete(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[llm-resilience] Request ended with orchestration context cancellation: %v", err)
			return nil, err
		}

		// Determine if the error is transient and should be retried
		if !r.isTransientError(err) {
			log.Printf("[ERROR] [llm-resilience] Non-transient error: %v. Aborting.", err)
			return nil, err
		}

		if attempt < r.maxRetries {
			delay := r.baseDelay * time.Duration(1<<uint(attempt))
			log.Printf("[WARN] [llm-resilience] Attempt %d/%d failed: %v. Retrying in %v...", attempt+1, r.maxRetries, err, delay)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("LLM connection failed after %d retries: %w", r.maxRetries, lastErr)
}

// isTransientError identifies errors that are likely to resolve on retry
func (r *ResilientProvider) isTransientError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())

	// Context cancellation is intentional, don't retry
	if strings.Contains(msg, "context canceled") {
		return false
	}

	transientSignals := []string{
		"429",                      // Rate limit
		"500", "502", "503", "504", // Server errors
		"timeout", "deadline exceeded",
		"connection refused",
		"reset by peer",
		"eof",
		"unrecognized sse event", // Potential Codex glitch
	}

	for _, signal := range transientSignals {
		if strings.Contains(msg, signal) {
			return true
		}
	}

	return false
}
