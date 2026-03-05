package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AgentStatus represents the current state of a specialist agent
type AgentStatus string

const (
	StatusIdle     AgentStatus = "idle"
	StatusRunning  AgentStatus = "running"
	StatusComplete AgentStatus = "complete"
	StatusFailed   AgentStatus = "failed"
	StatusTimeout  AgentStatus = "timeout"
)

// ActiveAgent tracks a running agent's metadata and cancellation function
type ActiveAgent struct {
	ID        uuid.UUID
	Type      string
	Target    string
	StartTime time.Time
	Status    AgentStatus
	cancelFn  context.CancelFunc
}

// Conductor oversees the Orchestrator, managing agent lifecycles, timeouts, and health
type Conductor struct {
	orchestrator *Orchestrator
	bus          *EventBus

	activeAgents map[uuid.UUID]*ActiveAgent
	agentMu      sync.RWMutex

	// Global scan timeout
	scanTimeout time.Duration
	// Per-agent timeout
	agentTimeout time.Duration
}

// NewConductor creates a new Conductor wrapping the given Orchestrator
func NewConductor(orch *Orchestrator, bus *EventBus) *Conductor {
	return &Conductor{
		orchestrator: orch,
		bus:          bus,
		activeAgents: make(map[uuid.UUID]*ActiveAgent),
		scanTimeout:  1 * time.Hour,    // Max time for an entire scan
		agentTimeout: 10 * time.Minute, // Max time for a single specialist
	}
}

// RunFlowWithOversight executes a scan with Conductor oversight
func (c *Conductor) RunFlowWithOversight(ctx context.Context, flowID uuid.UUID, userPrompt string) error {
	// Create a scan-level context with timeout
	scanCtx, cancelScan := context.WithTimeout(ctx, c.scanTimeout)
	defer cancelScan()

	// Wrap the orchestrator's RunFlow
	// Note: We need to modify Orchestrator.RunFlow slightly to accept the conductor
	// so the conductor can register agents before running them.
	// For now, we'll run it directly, but in a real system the Conductor would intercept the Swarm spawn.

	// Start a background health monitor for this scan
	go c.monitorHealth(scanCtx, flowID)

	c.emitStateUpdate(flowID, "Scan initialized, Conductor oversight active")

	err := c.orchestrator.RunFlow(scanCtx, flowID, userPrompt)

	c.emitStateUpdate(flowID, "Scan completed, Conductor shutting down")
	return err
}

// RegisterAgent tells the Conductor that a new specialist has started
func (c *Conductor) RegisterAgent(agentID uuid.UUID, agentType string, target string, cancelFn context.CancelFunc) {
	c.agentMu.Lock()
	c.activeAgents[agentID] = &ActiveAgent{
		ID:        agentID,
		Type:      agentType,
		Target:    target,
		StartTime: time.Now(),
		Status:    StatusRunning,
		cancelFn:  cancelFn,
	}
	c.agentMu.Unlock()

	c.emitQueueMetrics()
}

// DeregisterAgent removes an agent from active tracking
func (c *Conductor) DeregisterAgent(agentID uuid.UUID, finalStatus AgentStatus) {
	c.agentMu.Lock()
	if agent, ok := c.activeAgents[agentID]; ok {
		agent.Status = finalStatus
		// We could keep history of completed agents, but for now just delete
		delete(c.activeAgents, agentID)
	}
	c.agentMu.Unlock()

	c.emitQueueMetrics()
}

// monitorHealth runs in the background and kills hanging agents
func (c *Conductor) monitorHealth(ctx context.Context, flowID uuid.UUID) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.agentMu.RLock()
			now := time.Now()

			// Find lagging agents
			var toKill []uuid.UUID
			for id, agent := range c.activeAgents {
				if now.Sub(agent.StartTime) > c.agentTimeout {
					log.Printf("⚠️ Conductor: Agent %s (%s) exceeded timeout (%v). Terminating.", agent.ID, agent.Type, c.agentTimeout)
					toKill = append(toKill, id)
				}
			}
			c.agentMu.RUnlock()

			// Kill them
			for _, id := range toKill {
				c.agentMu.Lock()
				if agent, ok := c.activeAgents[id]; ok {
					agent.cancelFn() // Cancel the context for this specific agent
					agent.Status = StatusTimeout
					delete(c.activeAgents, id)

					// Inform the frontend
					c.orchestrator.emit(flowID.String(), Event{
						Type:    EventError,
						FlowID:  flowID.String(),
						TaskID:  "conductor",
						Content: fmt.Sprintf("Conductor terminated hanging agent: %s (%s)", agent.Type, agent.Target),
					})
				}
				c.agentMu.Unlock()
			}

			// Emit periodic state updates if agents are running
			c.agentMu.RLock()
			activeCount := len(c.activeAgents)
			c.agentMu.RUnlock()

			if activeCount > 0 {
				c.emitQueueMetrics()
			}
		}
	}
}

// emitQueueMetrics sends current active agent stats over the EventBus
func (c *Conductor) emitQueueMetrics() {
	c.agentMu.RLock()
	counts := make(map[string]int)
	for _, agent := range c.activeAgents {
		counts[agent.Type]++
	}
	total := len(c.activeAgents)
	c.agentMu.RUnlock()

	// Emit an internal event that server.go can broadcast
	c.bus.Emit(EventTypeInternal("queue_metrics"), map[string]interface{}{
		"total_active": total,
		"specialists":  counts,
	})
}

// emitStateUpdate sends a general system state update
func (c *Conductor) emitStateUpdate(flowID uuid.UUID, state string) {
	c.orchestrator.emit(flowID.String(), Event{
		Type:    EventMessage,
		FlowID:  flowID.String(),
		TaskID:  "conductor",
		Content: fmt.Sprintf("🚂 [Conductor Status]: %s", state),
	})
}
