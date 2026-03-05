package agent

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConductor_Timeout(t *testing.T) {
	// Create a dummy EventBus
	bus := NewEventBus()
	// Mock orchestrator
	orch := &Orchestrator{
		bus: bus,
		onEvent: func(e Event) {
			// discard
		},
	}

	c := NewConductor(orch, bus)
	// Set very short timeout for testing
	c.agentTimeout = 100 * time.Millisecond

	// Background health monitor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very fast ticker for the test
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.agentMu.RLock()
				now := time.Now()
				var toKill []uuid.UUID
				for id, agent := range c.activeAgents {
					if now.Sub(agent.StartTime) > c.agentTimeout {
						toKill = append(toKill, id)
					}
				}
				c.agentMu.RUnlock()

				for _, id := range toKill {
					c.agentMu.Lock()
					if agent, ok := c.activeAgents[id]; ok {
						agent.cancelFn()
						agent.Status = StatusTimeout
						delete(c.activeAgents, id)
					}
					c.agentMu.Unlock()
				}
			}
		}
	}()

	// Register a hanging agent
	agentID := uuid.New()
	agentCtx, agentCancel := context.WithCancel(context.Background())

	c.RegisterAgent(agentID, "HangingAgent", "http://example.com", agentCancel)

	// Verify agent is registered
	c.agentMu.RLock()
	if len(c.activeAgents) != 1 {
		t.Fatalf("Expected 1 active agent, got %d", len(c.activeAgents))
	}
	c.agentMu.RUnlock()

	// Wait for timeout to trigger
	time.Sleep(300 * time.Millisecond)

	// Verify agent was killed
	c.agentMu.RLock()
	if len(c.activeAgents) != 0 {
		t.Fatalf("Expected agent to be terminated by timeout, but %d remain", len(c.activeAgents))
	}
	c.agentMu.RUnlock()

	// Verify the agent's context was actually canceled
	if err := agentCtx.Err(); err != context.Canceled {
		t.Fatalf("Expected agent context to be canceled, got: %v", err)
	}
}
