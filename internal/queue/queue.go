// Package queue implements per-specialist async queues with backpressure
// and rate limiting.
//
// Each vulnerability specialist (XSS, SQLi, SSRF, etc.) gets its own queue.
// The ThinkingAgent routes findings into the correct queue, and specialist
// workers consume items concurrently.
package queue

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Item wraps a payload for the specialist queue.
type Item struct {
	Payload     map[string]interface{}
	ScanContext string
	EnqueuedAt  time.Time
}

// Stats tracks throughput and latency for a queue.
type Stats struct {
	Enqueued  int64
	Dequeued  int64
	Rejected  int64 // Rejected due to backpressure
	AvgLatMs  float64
	PeakDepth int
}

// SpecialistQueue is an async queue with backpressure and rate limiting.
//
// Features:
//   - Max depth enforcement (backpressure) — rejects items when full
//   - Token bucket rate limiting — prevents overloading the target
//   - Thread-safe for concurrent producers and consumers
type SpecialistQueue struct {
	Name      string
	MaxDepth  int        // 0 = unlimited
	RateLimit float64    // Items per second (0 = unlimited)
	ch        chan *Item // Buffered channel acts as the queue
	mu        sync.Mutex // Protects stats
	stats     Stats
	tokens    float64 // Token bucket
	lastToken time.Time
	closed    atomic.Bool
}

// NewSpecialistQueue creates a new queue for a specialist agent.
//
// Parameters:
//   - name: Queue identifier (e.g., "xss", "sqli")
//   - maxDepth: Maximum queue depth (0 = 1000 default)
//   - rateLimit: Max items/second consumed (0 = unlimited)
func NewSpecialistQueue(name string, maxDepth int, rateLimit float64) *SpecialistQueue {
	if maxDepth <= 0 {
		maxDepth = 1000
	}

	sq := &SpecialistQueue{
		Name:      name,
		MaxDepth:  maxDepth,
		RateLimit: rateLimit,
		ch:        make(chan *Item, maxDepth),
		tokens:    float64(maxDepth), // Start with full tokens
		lastToken: time.Now(),
	}

	return sq
}

// Enqueue adds an item to the queue.
// Returns false if the queue is full (backpressure).
func (sq *SpecialistQueue) Enqueue(payload map[string]interface{}, scanContext string) bool {
	if sq.closed.Load() {
		return false
	}

	item := &Item{
		Payload:     payload,
		ScanContext: scanContext,
		EnqueuedAt:  time.Now(),
	}

	select {
	case sq.ch <- item:
		sq.mu.Lock()
		atomic.AddInt64(&sq.stats.Enqueued, 1)
		depth := len(sq.ch)
		if depth > sq.stats.PeakDepth {
			sq.stats.PeakDepth = depth
		}
		sq.mu.Unlock()
		return true
	default:
		// Queue is full — backpressure
		atomic.AddInt64(&sq.stats.Rejected, 1)
		log.Printf("[queue:%s] Backpressure: queue full (%d/%d), item rejected",
			sq.Name, len(sq.ch), sq.MaxDepth)
		return false
	}
}

// Dequeue retrieves the next item from the queue.
// Blocks until an item is available or the timeout expires.
// Returns nil if timeout or queue is closed.
func (sq *SpecialistQueue) Dequeue(timeout time.Duration) *Item {
	// Apply rate limiting if configured
	if sq.RateLimit > 0 {
		sq.waitForToken()
	}

	if timeout <= 0 {
		// Non-blocking
		select {
		case item := <-sq.ch:
			sq.recordDequeue(item)
			return item
		default:
			return nil
		}
	}

	// Blocking with timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case item := <-sq.ch:
		sq.recordDequeue(item)
		return item
	case <-timer.C:
		return nil
	}
}

// waitForToken implements the token bucket rate limiter.
func (sq *SpecialistQueue) waitForToken() {
	sq.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(sq.lastToken).Seconds()
	sq.tokens += elapsed * sq.RateLimit
	if sq.tokens > float64(sq.MaxDepth) {
		sq.tokens = float64(sq.MaxDepth)
	}
	sq.lastToken = now

	if sq.tokens >= 1.0 {
		sq.tokens -= 1.0
		sq.mu.Unlock()
		return
	}

	// Need to wait for a token
	waitTime := time.Duration((1.0 - sq.tokens) / sq.RateLimit * float64(time.Second))
	sq.mu.Unlock()

	time.Sleep(waitTime)

	sq.mu.Lock()
	sq.tokens = 0
	sq.lastToken = time.Now()
	sq.mu.Unlock()
}

func (sq *SpecialistQueue) recordDequeue(item *Item) {
	latency := time.Since(item.EnqueuedAt)
	sq.mu.Lock()
	atomic.AddInt64(&sq.stats.Dequeued, 1)
	// Simple moving average
	dequeued := float64(atomic.LoadInt64(&sq.stats.Dequeued))
	sq.stats.AvgLatMs = sq.stats.AvgLatMs + (float64(latency.Milliseconds())-sq.stats.AvgLatMs)/dequeued
	sq.mu.Unlock()
}

// Depth returns the current number of items in the queue.
func (sq *SpecialistQueue) Depth() int {
	return len(sq.ch)
}

// IsFull returns true if the queue has reached max depth.
func (sq *SpecialistQueue) IsFull() bool {
	return len(sq.ch) >= sq.MaxDepth
}

// Close closes the queue, preventing new items and unblocking consumers.
func (sq *SpecialistQueue) Close() {
	if sq.closed.CompareAndSwap(false, true) {
		close(sq.ch)
	}
}

// GetStats returns a copy of the queue statistics.
func (sq *SpecialistQueue) GetStats() Stats {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	return Stats{
		Enqueued:  atomic.LoadInt64(&sq.stats.Enqueued),
		Dequeued:  atomic.LoadInt64(&sq.stats.Dequeued),
		Rejected:  atomic.LoadInt64(&sq.stats.Rejected),
		AvgLatMs:  sq.stats.AvgLatMs,
		PeakDepth: sq.stats.PeakDepth,
	}
}

// --- Queue Manager ---

// Manager is a registry of all specialist queues.
// It provides a single point to inspect and manage all queues.
type Manager struct {
	mu     sync.RWMutex
	queues map[string]*SpecialistQueue
}

// NewManager creates a new queue manager.
func NewManager() *Manager {
	return &Manager{
		queues: make(map[string]*SpecialistQueue),
	}
}

// Register creates and registers a new specialist queue.
func (m *Manager) Register(name string, maxDepth int, rateLimit float64) *SpecialistQueue {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.queues[name]; ok {
		return existing
	}

	q := NewSpecialistQueue(name, maxDepth, rateLimit)
	m.queues[name] = q
	log.Printf("[queue-manager] Registered queue: %s (depth=%d, rate=%.1f/s)", name, maxDepth, rateLimit)
	return q
}

// Get returns the queue for a specialist, or nil if not found.
func (m *Manager) Get(name string) *SpecialistQueue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.queues[name]
}

// Route enqueues a finding payload into the correct specialist queue.
// Returns an error if the queue doesn't exist or is full.
func (m *Manager) Route(specialist string, payload map[string]interface{}, scanContext string) error {
	q := m.Get(specialist)
	if q == nil {
		return fmt.Errorf("no queue registered for specialist: %s", specialist)
	}

	if !q.Enqueue(payload, scanContext) {
		return fmt.Errorf("queue %s is full (backpressure)", specialist)
	}

	return nil
}

// GetAllStats returns stats for all registered queues.
func (m *Manager) GetAllStats() map[string]Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]Stats, len(m.queues))
	for name, q := range m.queues {
		stats[name] = q.GetStats()
	}
	return stats
}

// CloseAll closes all registered queues.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, q := range m.queues {
		q.Close()
		log.Printf("[queue-manager] Closed queue: %s", name)
	}
}

// DrainAll waits until all queues are empty or timeout expires.
func (m *Manager) DrainAll(timeout time.Duration) map[string]int {
	deadline := time.After(timeout)
	result := make(map[string]int)

	m.mu.RLock()
	names := make([]string, 0, len(m.queues))
	for name := range m.queues {
		names = append(names, name)
	}
	m.mu.RUnlock()

	for {
		allEmpty := true
		for _, name := range names {
			q := m.Get(name)
			if q != nil && q.Depth() > 0 {
				allEmpty = false
				break
			}
		}

		if allEmpty {
			for _, name := range names {
				q := m.Get(name)
				if q != nil {
					result[name] = int(q.GetStats().Dequeued)
				}
			}
			return result
		}

		select {
		case <-deadline:
			log.Printf("[queue-manager] Drain timeout after %v", timeout)
			for _, name := range names {
				q := m.Get(name)
				if q != nil {
					result[name] = int(q.GetStats().Dequeued)
				}
			}
			return result
		case <-time.After(100 * time.Millisecond):
			// Poll again
		}
	}
}
