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
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/queue"
	"github.com/google/uuid"
)

// Re-export base types for internal/agent package scope if needed
type Finding = base.Finding
type Specialist = base.Specialist

var ValidateFinding = base.ValidateFinding

func shouldRouteFindingToLead(f *Finding) bool {
	return !findingHasConcreteEvidence(f)
}

func findingLeadNote(f *Finding) string {
	if f == nil {
		return "Needs validation: unknown finding"
	}

	note := fmt.Sprintf("Needs validation: %s at %s", f.Type, f.URL)
	if f.Parameter != "" {
		note += fmt.Sprintf(" (param: %s)", f.Parameter)
	}

	if f.Evidence != nil {
		for _, key := range []string{"category", "task", "technique", "xss_type", "sqli_type", "source", "context", "field", "section"} {
			if raw, ok := f.Evidence[key]; ok {
				hint := strings.TrimSpace(fmt.Sprint(raw))
				if hint != "" {
					note += fmt.Sprintf(" [%s]", hint)
					break
				}
			}
		}
	}

	return note
}

func payloadUUID(payload map[string]interface{}, key string) *uuid.UUID {
	if payload == nil {
		return nil
	}
	raw, ok := payload[key]
	if !ok {
		return nil
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		return nil
	}
	return &parsed
}

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
	var skeptic *Skeptic
	if orch != nil && orch.llmProvider != nil {
		skeptic = NewSkeptic(orch.llmProvider)
	}
	return &Worker{
		specialist:   spec,
		queue:        q,
		concurrency:  concurrency,
		findings:     make([]*Finding, 0),
		onFinding:    onFinding,
		manipulator:  NewManipulator(),
		skeptic:      skeptic,
		orchestrator: orch,
	}
}

// Start begins consuming items from the queue with the configured concurrency.
// Blocks until the context is cancelled or the queue is closed.
func (w *Worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	// Propagate the orchestrator's ScopeEngine to every downstream HTTP
	// probe via context. Specialists that use FuzzClient will refuse
	// out-of-scope requests rather than silently hit whatever URL the
	// LLM produced.
	if w.orchestrator != nil && w.orchestrator.scope != nil {
		ctx = base.WithScope(ctx, w.orchestrator.scope)
	}
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
			flowID := payloadUUID(item.Payload, "_flow_id")
			taskID := payloadUUID(item.Payload, "_task_id")
			subtaskID := payloadUUID(item.Payload, "_subtask_id")
			if subtaskID != nil && w.orchestrator != nil {
				w.orchestrator.updateLedgerSubTask(*subtaskID, models.SubTaskStatusRunning, "", models.SubTaskOutcomeRunning, map[string]any{
					"agent": w.specialist.Name(),
				})
			}

			findings, err := w.specialist.ProcessItem(ctx, item)
			if err != nil {
				log.Printf("[worker:%s] Error processing item: %v", w.specialist.Name(), err)
				if subtaskID != nil && w.orchestrator != nil {
					w.orchestrator.updateLedgerSubTask(*subtaskID, models.SubTaskStatusFailed, err.Error(), models.SubTaskOutcomeBlockedByRuntime, map[string]any{
						"agent": w.specialist.Name(),
					})
				}
				return
			}

			confirmedCount := 0
			needsProofCount := 0
			rejectedCount := 0

			for _, f := range findings {
				if f == nil {
					rejectedCount++
					continue
				}

				f.Agent = w.specialist.Name()
				f.Timestamp = time.Now()
				if subtaskID != nil {
					f.SubTaskID = subtaskID.String()
				}

				if shouldRouteFindingToLead(f) {
					if err := base.ValidateFindingSurface(f); err != nil {
						log.Printf("[worker:%s] Finding rejected (surface validation): %v", w.specialist.Name(), err)
						rejectedCount++
						if flowID != nil && w.orchestrator != nil {
							w.orchestrator.recordEvidencePack(*flowID, taskID, subtaskID, f, models.EvidenceStatusRejected, err.Error())
						}
						continue
					}

					needsProofCount++
					summary := "candidate generated without request/response, browser, timing, or OOB proof"
					if flowID != nil && w.orchestrator != nil {
						w.orchestrator.recordEvidencePack(*flowID, taskID, subtaskID, f, models.EvidenceStatusNeedsProof, summary)
						if w.orchestrator.bus != nil {
							w.orchestrator.bus.Emit(EventLeadDiscovered, findingLeadNote(f))
						}
					}
					continue
				}

				if err := ValidateFinding(f); err != nil {
					log.Printf("[worker:%s] Finding rejected (basic validation): %v", w.specialist.Name(), err)
					rejectedCount++
					if flowID != nil && w.orchestrator != nil {
						w.orchestrator.recordEvidencePack(*flowID, taskID, subtaskID, f, models.EvidenceStatusRejected, err.Error())
					}
					continue
				}

				// Phase 15: The Skeptic's Audit
				if w.skeptic != nil {
					audit, err := w.skeptic.Audit(ctx, f)
					if err == nil && audit.IsFalsePositive {
						log.Printf("[worker:%s] Skeptic REJECTED finding as false positive: %s (Reason: %s)",
							w.specialist.Name(), f.Type, audit.Reasoning)
						rejectedCount++
						if flowID != nil && w.orchestrator != nil {
							w.orchestrator.recordEvidencePack(*flowID, taskID, subtaskID, f, models.EvidenceStatusRejected, audit.Reasoning)
						}
						continue
					}
					if err == nil {
						f.Confidence = float64(audit.Confidence) / 100.0
					}
				}

				status := models.EvidenceStatusConfirmed
				summary := "validated by specialist"
				if ok, reason := shouldPromoteFinding(f); !ok {
					status = models.EvidenceStatusNeedsProof
					summary = reason
					needsProofCount++
				} else {
					confirmedCount++
				}
				if flowID != nil && w.orchestrator != nil {
					w.orchestrator.recordEvidencePack(*flowID, taskID, subtaskID, f, status, summary)
				}
				if status != models.EvidenceStatusConfirmed {
					if w.orchestrator != nil && w.orchestrator.bus != nil {
						w.orchestrator.bus.Emit(EventLeadDiscovered, findingLeadNote(f))
					}
					continue
				}

				// Phase 15: Record finding in payload success memory
				if w.orchestrator != nil && w.orchestrator.memory != nil && f.Payload != "" {
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

			if subtaskID != nil && w.orchestrator != nil {
				status := models.SubTaskStatusCompleted
				outcome := models.SubTaskOutcomeExhausted
				result := "No validated or evidence-bearing findings emitted."
				switch {
				case confirmedCount > 0:
					outcome = models.SubTaskOutcomeConfirmed
					result = fmt.Sprintf("Confirmed %d finding(s); %d need more proof; %d rejected.", confirmedCount, needsProofCount, rejectedCount)
				case needsProofCount > 0:
					outcome = models.SubTaskOutcomeNeedsProof
					result = fmt.Sprintf("%d candidate finding(s) need more proof; %d rejected.", needsProofCount, rejectedCount)
				case rejectedCount > 0:
					outcome = models.SubTaskOutcomeRejected
					result = fmt.Sprintf("Rejected %d speculative finding(s).", rejectedCount)
				}
				w.orchestrator.updateLedgerSubTask(*subtaskID, status, result, outcome, map[string]any{
					"agent":             w.specialist.Name(),
					"confirmed_count":   confirmedCount,
					"needs_proof_count": needsProofCount,
					"rejected_count":    rejectedCount,
				})
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
