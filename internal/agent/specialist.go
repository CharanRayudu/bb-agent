// Package agent defines the Specialist interface and base utilities that
// all vulnerability-specific agents must implement.
//
// This implements the BaseAgent pattern in idiomatic Go:
//   - Interface-based polymorphism
//   - Goroutines for concurrency
//   - Channels for pause/resume
package agent

import (
	"context"
	"log"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Re-export base types for internal/agent package scope if needed
type Finding = base.Finding
type Specialist = base.Specialist

var ValidateFinding = base.ValidateFinding

// Worker runs a specialist agent as a queue consumer.
// It pulls items from the specialist's queue and processes them using goroutines.
type Worker struct {
	specialist  Specialist
	queue       *queue.SpecialistQueue
	concurrency int
	findings    []*Finding
	onFinding   func(*Finding) // Callback when a finding is emitted
	cancel      context.CancelFunc

	// Phase 15: precision tools
	manipulator  *Manipulator
	skeptic      *Skeptic
	orchestrator *Orchestrator
}

// NewWorker creates a worker for a specialist agent.
func NewWorker(spec Specialist, q *queue.SpecialistQueue, concurrency int, onFinding func(*Finding), orch *Orchestrator) *Worker {
	if concurrency <= 0 {
		concurrency = 1
	}
	return &Worker{
		specialist:   spec,
		queue:        q,
		concurrency:  concurrency,
		findings:     make([]*Finding, 0),
		onFinding:    onFinding,
		manipulator:  NewManipulator(),
		skeptic:      NewSkeptic(orch.llmProvider),
		orchestrator: orch,
	}
}

// Start begins consuming items from the queue with the configured concurrency.
// Blocks until the context is cancelled or the queue is closed.
func (w *Worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	sem := make(chan struct{}, w.concurrency)

	log.Printf("[worker:%s] Started with concurrency=%d", w.specialist.Name(), w.concurrency)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[worker:%s] Shutting down", w.specialist.Name())
			return
		default:
		}

		item := w.queue.Dequeue(500 * time.Millisecond)
		if item == nil {
			continue
		}

		sem <- struct{}{} // Acquire semaphore
		go func(item *queue.Item) {
			defer func() { <-sem }() // Release semaphore

			findings, err := w.specialist.ProcessItem(ctx, item)
			if err != nil {
				log.Printf("[worker:%s] Error processing item: %v", w.specialist.Name(), err)
				return
			}

			for _, f := range findings {
				if err := ValidateFinding(f); err != nil {
					log.Printf("[worker:%s] Finding rejected (basic validation): %v", w.specialist.Name(), err)
					continue
				}

				// Phase 15: The Skeptic's Audit
				if w.skeptic != nil {
					audit, err := w.skeptic.Audit(ctx, f)
					if err == nil && audit.IsFalsePositive {
						log.Printf("[worker:%s] Skeptic REJECTED finding as false positive: %s (Reason: %s)",
							w.specialist.Name(), f.Type, audit.Reasoning)
						continue
					}
					if err == nil {
						f.Confidence = float64(audit.Confidence) / 100.0
					}
				}

				f.Agent = w.specialist.Name()
				f.Timestamp = time.Now()

				// Phase 15: Record finding in payload success memory
				if w.orchestrator.memory != nil && f.Payload != "" {
					tech := "generic"
					if w.orchestrator.pipeline != nil {
						// Extract tech stack from context if possible
					}
					w.orchestrator.memory.RecordPayloadResult(tech, f.Type, f.Payload, true)
				}

				if w.onFinding != nil {
					w.onFinding(f)
				}
			}
		}(item)
	}
}

// Stop signals the worker to stop consuming items.
func (w *Worker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

// --- Finding Validation ---

// ValidateFinding is handled by base
