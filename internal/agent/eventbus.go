package agent

import (
	"sync"
)

// EventType is the type of event emitted by agents
type EventTypeInternal string

const (
	// EventFindingDiscovered is emitted when an agent finds a potential bug
	EventFindingDiscovered EventTypeInternal = "finding_discovered"
	// EventLeadDiscovered is emitted when an agent finds a lead that isn't yet a bug
	EventLeadDiscovered EventTypeInternal = "lead_discovered"
	// EventExclusionDiscovered is emitted when an agent determines something is a dead end
	EventExclusionDiscovered EventTypeInternal = "exclusion_discovered"
	// EventPivotDiscovered is emitted when an agent discovers something that unlocks
	// a new attack surface, warranting a pipeline restart. Examples: credentials,
	// new subdomains, SSRF-accessible internal endpoints, API keys, JWT secrets, etc.
	EventPivotDiscovered EventTypeInternal = "pivot_discovered"

	// Causal Graph Events
	EventCausalNodeAdded   EventTypeInternal = "causal_node_added"
	EventCausalNodeUpdated EventTypeInternal = "causal_node_updated"
	EventCausalEdgeAdded   EventTypeInternal = "causal_edge_added"

	// EventBrainUpdate is emitted when the brain needs a structured update
	EventBrainUpdate EventTypeInternal = "brain_update"
)

// EventBus handles internal communication between agents.
// Durable subscribers survive Reset so process-level listeners, such as the
// WebSocket metrics bridge, are not removed when a scan starts.
type EventBus struct {
	subscribers map[EventTypeInternal][]func(data interface{})
	durable     map[EventTypeInternal][]func(data interface{})
	mu          sync.RWMutex
}

// NewEventBus creates a new internal event bus
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[EventTypeInternal][]func(data interface{})),
		durable:     make(map[EventTypeInternal][]func(data interface{})),
	}
}

// Subscribe adds a handler for a specific event type
func (eb *EventBus) Subscribe(eventType EventTypeInternal, handler func(data interface{})) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.subscribers[eventType] = append(eb.subscribers[eventType], handler)
}

// SubscribeDurable registers a listener that Reset will not remove.
func (eb *EventBus) SubscribeDurable(eventType EventTypeInternal, handler func(data interface{})) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	if eb.durable == nil {
		eb.durable = make(map[EventTypeInternal][]func(data interface{}))
	}
	eb.durable[eventType] = append(eb.durable[eventType], handler)
}

// Emit triggers all handlers for a specific event type
func (eb *EventBus) Emit(eventType EventTypeInternal, data interface{}) {
	eb.mu.RLock()
	handlers := append([]func(data interface{}){}, eb.subscribers[eventType]...)
	handlers = append(handlers, eb.durable[eventType]...)
	eb.mu.RUnlock()

	for _, handler := range handlers {
		// Run handlers in a goroutine to avoid blocking the emitter
		go handler(data)
	}
}

// Reset removes scan-local subscribers. Durable listeners stay attached.
func (eb *EventBus) Reset() {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.subscribers = make(map[EventTypeInternal][]func(data interface{}))
}
