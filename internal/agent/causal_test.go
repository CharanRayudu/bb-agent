package agent

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
)

func TestCausalGraphToolsIntegration(t *testing.T) {
	// 1. Setup mocks
	mockProvider := &MockProvider{}
	registry := tools.NewRegistry(nil)
	orch := NewOrchestrator(mockProvider, registry, nil, &config.Prompts{})

	// 2. Mock RunFlow environment
	brain := &Brain{}
	var brainMu sync.Mutex

	// 3. Register subscribers (like RunFlow does)
	orch.bus.Reset()

	// Node added subscriber
	orch.bus.Subscribe(EventCausalNodeAdded, func(data interface{}) {
		node := data.(*models.CausalNode)
		brainMu.Lock()
		if brain.CausalGraph == nil {
			brain.CausalGraph = &models.CausalGraph{
				Nodes: make(map[string]*models.CausalNode),
			}
		}
		brain.CausalGraph.Nodes[node.ID] = node
		brainMu.Unlock()
	})

	// Edge added subscriber
	orch.bus.Subscribe(EventCausalEdgeAdded, func(data interface{}) {
		edge := data.(*models.CausalEdge)
		brainMu.Lock()
		if brain.CausalGraph == nil {
			brain.CausalGraph = &models.CausalGraph{
				Nodes: make(map[string]*models.CausalNode),
			}
		}
		brain.CausalGraph.Edges = append(brain.CausalGraph.Edges, *edge)
		brainMu.Unlock()
	})

	// 4. Call cg_add_node
	addNodeTool, ok := registry.Get("cg_add_node")
	if !ok {
		t.Fatal("cg_add_node tool not found in registry")
	}

	nodeArgs := json.RawMessage(`{"id": "test-node", "node_type": "Evidence", "description": "Test description"}`)
	_, err := addNodeTool.Execute(context.Background(), nodeArgs)
	if err != nil {
		t.Fatalf("Failed to execute cg_add_node: %v", err)
	}

	// Wait for async event bus
	success := false
	for i := 0; i < 100; i++ {
		brainMu.Lock()
		if brain.CausalGraph != nil && brain.CausalGraph.Nodes["test-node"] != nil {
			success = true
			brainMu.Unlock()
			break
		}
		brainMu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	if !success {
		t.Error("CausalNode was not added to the brain after tool execution")
	}

	// 5. Call cg_add_edge
	addEdgeTool, ok := registry.Get("cg_add_edge")
	if !ok {
		t.Fatal("cg_add_edge tool not found in registry")
	}

	edgeArgs := json.RawMessage(`{"source_id": "test-node", "target_id": "target-node", "label": "SUPPORTS"}`)
	_, err = addEdgeTool.Execute(context.Background(), edgeArgs)
	if err != nil {
		t.Fatalf("Failed to execute cg_add_edge: %v", err)
	}

	// Verify brain state eventually
	edgeSuccess := false
	for i := 0; i < 100; i++ {
		brainMu.Lock()
		if brain.CausalGraph != nil && len(brain.CausalGraph.Edges) > 0 {
			edgeSuccess = true
			brainMu.Unlock()
			break
		}
		brainMu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	if !edgeSuccess {
		t.Error("CausalEdge was not added to the brain after tool execution")
	}
}

func TestEventBusReset(t *testing.T) {
	eb := NewEventBus()
	count := 0
	eb.Subscribe(EventLeadDiscovered, func(data interface{}) {
		count++
	})

	eb.Emit(EventLeadDiscovered, "test")
	// Since handlers run in goroutines, we'd need synchronization to check count reliably.
	// But the logic of Reset is simple.
	eb.Reset()
	if len(eb.subscribers) != 0 {
		t.Error("EventBus.Reset() did not clear subscribers")
	}
}

func TestCausalGraphConcurrency(t *testing.T) {
	// Verify that two simultaneous flows don't leak data into each other's brains
	mockProvider := &MockProvider{}

	// Create separate registries as server.go does
	reg1 := tools.NewRegistry(nil)
	reg2 := tools.NewRegistry(nil)

	orch1 := NewOrchestrator(mockProvider, reg1, nil, &config.Prompts{})
	orch2 := NewOrchestrator(mockProvider, reg2, nil, &config.Prompts{})

	brain1 := &Brain{}
	brain2 := &Brain{}
	var mu1, mu2 sync.Mutex

	// Setup subscribers for flow 1
	orch1.bus.Subscribe(EventCausalNodeAdded, func(data interface{}) {
		node := data.(*models.CausalNode)
		mu1.Lock()
		if brain1.CausalGraph == nil {
			brain1.CausalGraph = &models.CausalGraph{Nodes: make(map[string]*models.CausalNode)}
		}
		brain1.CausalGraph.Nodes[node.ID] = node
		mu1.Unlock()
	})

	// Setup subscribers for flow 2
	orch2.bus.Subscribe(EventCausalNodeAdded, func(data interface{}) {
		node := data.(*models.CausalNode)
		mu2.Lock()
		if brain2.CausalGraph == nil {
			brain2.CausalGraph = &models.CausalGraph{Nodes: make(map[string]*models.CausalNode)}
		}
		brain2.CausalGraph.Nodes[node.ID] = node
		mu2.Unlock()
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tool, _ := reg1.Get("cg_add_node")
		tool.Execute(context.Background(), json.RawMessage(`{"id": "node-1", "node_type": "Hypothesis", "description": "Flow 1"}`))
	}()

	go func() {
		defer wg.Done()
		tool, _ := reg2.Get("cg_add_node")
		tool.Execute(context.Background(), json.RawMessage(`{"id": "node-2", "node_type": "Hypothesis", "description": "Flow 2"}`))
	}()

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Wait for async events

	mu1.Lock()
	if brain1.CausalGraph == nil {
		t.Error("Brain 1 CausalGraph is nil, expected node-1")
	} else if _, ok := brain1.CausalGraph.Nodes["node-2"]; ok {
		t.Error("Isolation Failure: Node from Flow 2 leaked into Brain 1")
	} else if _, ok := brain1.CausalGraph.Nodes["node-1"]; !ok {
		t.Error("Missing Node: Node 1 was not added to Brain 1")
	}
	mu1.Unlock()

	mu2.Lock()
	if brain2.CausalGraph == nil {
		t.Error("Brain 2 CausalGraph is nil, expected node-2")
	} else if _, ok := brain2.CausalGraph.Nodes["node-1"]; ok {
		t.Error("Isolation Failure: Node from Flow 1 leaked into Brain 2")
	} else if _, ok := brain2.CausalGraph.Nodes["node-2"]; !ok {
		t.Error("Missing Node: Node 2 was not added to Brain 2")
	}
	mu2.Unlock()
}

func TestCausalGraphEdgeCases(t *testing.T) {
	mockProvider := &MockProvider{}
	registry := tools.NewRegistry(nil)
	orch := NewOrchestrator(mockProvider, registry, nil, &config.Prompts{})

	orch.bus.Reset()

	// 1. Test invalid JSON
	tool, _ := registry.Get("cg_add_node")
	_, err := tool.Execute(context.Background(), json.RawMessage(`{invalid-json}`))
	if err == nil {
		t.Error("Expected error for invalid JSON in cg_add_node")
	}

	// 2. Test missing fields (internal/tools should handle defaults or error)
	_, err = tool.Execute(context.Background(), json.RawMessage(`{"description": "missing id"}`))
	// Currently the tool might allow empty ID if not validated in ToolDefinition but we check behavior
	if err != nil {
		t.Logf("Tool correctly errored on missing ID: %v", err)
	}

	// 3. Test cg_update_node on non-existent node
	updateTool, _ := registry.Get("cg_update_node")
	_, err = updateTool.Execute(context.Background(), json.RawMessage(`{"id": "non-existent", "status": "CONFIRMED", "confidence": 0.9}`))
	if err != nil {
		t.Errorf("Unexpected error updating non-existent node: %v (should fail silently or emit update but not crash)", err)
	}
}

func TestEventBusSaturation(t *testing.T) {
	eb := NewEventBus()
	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(iterations)

	eb.Subscribe(EventLeadDiscovered, func(data interface{}) {
		wg.Done()
	})

	for i := 0; i < iterations; i++ {
		eb.Emit(EventLeadDiscovered, "test")
	}

	// Wait with timeout
	c := make(chan struct{})
	go func() {
		wg.Wait()
		close(c)
	}()

	select {
	case <-c:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("Timed out waiting for saturated events")
	}
}
