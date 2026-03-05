package agent

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
)

// StubProvider allows pre-defining a sequence of LLM responses
type StubProvider struct {
	Responses []*llm.CompletionResponse
	index     int
	mu        sync.Mutex
}

func (p *StubProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.index >= len(p.Responses) {
		return &llm.CompletionResponse{Content: "No more mock responses"}, nil
	}
	res := p.Responses[p.index]
	p.index++
	return res, nil
}

func (p *StubProvider) Name() string { return "stub" }

func TestOrchestratorInit(t *testing.T) {
	stub := &StubProvider{}
	registry := tools.NewRegistry(nil)
	orch := NewOrchestrator(stub, registry, nil, &config.Prompts{})
	if orch == nil {
		t.Fatal("Failed to init orchestrator")
	}
	fmt.Println("Init test passed")
}

func TestSystemEndToEndCausalFlow(t *testing.T) {
	stub := &StubProvider{}
	registry := tools.NewRegistry(nil)
	orch := NewOrchestrator(stub, registry, nil, &config.Prompts{})

	flowID := uuid.New()

	stub.Responses = append(stub.Responses, &llm.CompletionResponse{
		Content: "Step 1",
		ToolCalls: []models.ToolCall{
			{
				ID:        "call_1",
				Name:      "cg_add_node",
				Arguments: `{"id": "node-1", "node_type": "Hypothesis", "description": "desc"}`,
			},
		},
	})

	stub.Responses = append(stub.Responses, &llm.CompletionResponse{
		Content: "Step 2",
		ToolCalls: []models.ToolCall{
			{
				ID:        "call_2",
				Name:      "cg_update_node",
				Arguments: `{"id": "node-1", "status": "CONFIRMED", "confidence": 0.99}`,
			},
		},
	})

	brain := &Brain{}
	var brainMu sync.Mutex

	orch.bus.Reset()
	orch.bus.Subscribe(EventCausalNodeAdded, func(data interface{}) {
		node := data.(*models.CausalNode)
		brainMu.Lock()
		if brain.CausalGraph == nil {
			brain.CausalGraph = &models.CausalGraph{Nodes: make(map[string]*models.CausalNode)}
		}
		brain.CausalGraph.Nodes[node.ID] = node
		brainMu.Unlock()
	})
	orch.bus.Subscribe(EventCausalNodeUpdated, func(data interface{}) {
		params := data.(map[string]interface{})
		id := params["id"].(string)
		status := params["status"].(string)
		confidence := params["confidence"].(float64)
		brainMu.Lock()
		if brain.CausalGraph != nil {
			if node, ok := brain.CausalGraph.Nodes[id]; ok {
				node.Status = status
				node.Confidence = confidence
			}
		}
		brainMu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	taskID := uuid.New()
	subtaskID := uuid.New()

	orch.runAgentLoop(ctx, flowID, taskID, subtaskID, "system", "user", brain, &brainMu)
	time.Sleep(50 * time.Millisecond)

	brainMu.Lock()
	if brain.CausalGraph == nil || brain.CausalGraph.Nodes["node-1"] == nil {
		t.Fatal("Node not added")
	}
	brainMu.Unlock()

	orch.runAgentLoop(ctx, flowID, taskID, subtaskID, "system", "user", brain, &brainMu)
	time.Sleep(50 * time.Millisecond)

	brainMu.Lock()
	if brain.CausalGraph.Nodes["node-1"].Status != "CONFIRMED" {
		t.Fatal("Node not updated")
	}
	brainMu.Unlock()

	fmt.Println("Integration Test Passed")
}
