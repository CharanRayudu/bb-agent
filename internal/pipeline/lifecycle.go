package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/queue"
)

// Lifecycle manages graceful pipeline operations: pause, resume, drain, shutdown.
//
// It coordinates with worker pools registered by the orchestrator.
// Uses Go's context + WaitGroup for state management.
type Lifecycle struct {
	state    *State
	queueMgr *queue.Manager

	mu       sync.RWMutex
	pauseCh  chan struct{} // Closed to signal pause
	resumeCh chan struct{} // Closed to signal resume
	isPaused bool

	// Shutdown coordination
	shutdownOnce sync.Once
	wg           sync.WaitGroup // Tracks active workers
}

// NewLifecycle creates a lifecycle manager for the given pipeline state.
func NewLifecycle(state *State, queueMgr *queue.Manager) *Lifecycle {
	return &Lifecycle{
		state:    state,
		queueMgr: queueMgr,
		pauseCh:  make(chan struct{}),
		resumeCh: make(chan struct{}),
	}
}

// TrackWorker increments the active worker count.
// Call this before starting a specialist worker.
func (l *Lifecycle) TrackWorker() {
	l.wg.Add(1)
}

// WorkerDone decrements the active worker count.
// Call this when a specialist worker finishes.
func (l *Lifecycle) WorkerDone() {
	l.wg.Done()
}

// Pause signals all workers to pause at the next checkpoint.
// Workers should call CheckPausePoint() regularly to respond.
func (l *Lifecycle) Pause(reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isPaused {
		return nil
	}

	err := l.state.Pause(reason)
	if err != nil {
		return err
	}

	l.isPaused = true
	close(l.pauseCh)
	l.resumeCh = make(chan struct{}) // New resume channel for this pause cycle
	log.Printf("[lifecycle] Pipeline PAUSED: %s", reason)
	return nil
}

// Resume signals all paused workers to resume.
func (l *Lifecycle) Resume() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.isPaused {
		return nil
	}

	err := l.state.Resume()
	if err != nil {
		return err
	}

	l.isPaused = false
	close(l.resumeCh)
	l.pauseCh = make(chan struct{}) // New pause channel for next cycle
	log.Printf("[lifecycle] Pipeline RESUMED")
	return nil
}

// CheckPausePoint should be called by workers at safe points.
// If the pipeline is paused, this blocks until resumed or the context is cancelled.
// Returns true if the worker should stop (context cancelled).
func (l *Lifecycle) CheckPausePoint(ctx context.Context) bool {
	l.mu.RLock()
	paused := l.isPaused
	resumeCh := l.resumeCh
	l.mu.RUnlock()

	if !paused {
		return false
	}

	log.Printf("[lifecycle] Worker paused, waiting for resume...")
	select {
	case <-resumeCh:
		return false
	case <-ctx.Done():
		return true
	}
}

// Drain waits for all queues to empty or timeout.
func (l *Lifecycle) Drain(timeout time.Duration) map[string]int {
	log.Printf("[lifecycle] Draining queues (timeout=%v)...", timeout)
	return l.queueMgr.DrainAll(timeout)
}

// Shutdown performs a graceful shutdown:
// 1. Signal all queues to close (no new items)
// 2. Wait for workers to finish current items
// 3. Drain remaining items
func (l *Lifecycle) Shutdown(ctx context.Context, drainTimeout time.Duration) {
	l.shutdownOnce.Do(func() {
		log.Printf("[lifecycle] Initiating graceful shutdown...")

		// Close all queues (producers can't enqueue, consumers will drain)
		l.queueMgr.CloseAll()

		// Wait for active workers to finish (with timeout)
		done := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Printf("[lifecycle] All workers finished cleanly")
		case <-time.After(drainTimeout):
			log.Printf("[lifecycle] Shutdown timeout — some workers may still be running")
		case <-ctx.Done():
			log.Printf("[lifecycle] Shutdown cancelled by context")
		}
	})
}
