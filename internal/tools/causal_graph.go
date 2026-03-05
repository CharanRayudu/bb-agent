package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bb-agent/mirage/internal/llm"
)

// AddCausalGraphTools registers tools for manipulating the Causal Evidence Graph
func (r *Registry) AddCausalGraphTools(
	onAddNode func(id, nodeType, description string),
	onUpdateNode func(id, status string, confidence float64),
	onAddEdge func(sourceID, targetID, label string),
) {
	// Tool 1: cg_add_node
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "cg_add_node",
			Description: "Add a new node to the Causal Evidence Graph. This represents a hypothesis, a piece of evidence, or a discovered vulnerability. Use this to track reasoning beyond simple findings.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Unique identifier for the node (e.g., 'hyp-sqli-api', 'ev-auth-log')",
					},
					"node_type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"Evidence", "Hypothesis", "Vulnerability", "Fact"},
						"description": "The category of the node.",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable description of what this node represents.",
					},
				},
				"required": []string{"id", "node_type", "description"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				ID          string `json:"id"`
				NodeType    string `json:"node_type"`
				Description string `json:"description"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			onAddNode(params.ID, params.NodeType, params.Description)
			return fmt.Sprintf("CausalNode added: [%s] %s (%s)", params.NodeType, params.ID, params.Description), nil
		},
	})

	// Tool 2: cg_update_node
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "cg_update_node",
			Description: "Update an existing node's status or confidence in the Causal Evidence Graph based on new evidence or validation results.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "ID of the node to update",
					},
					"status": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"PENDING", "CONFIRMED", "FALSIFIED", "DEPRECATED"},
						"description": "New status for the node",
					},
					"confidence": map[string]interface{}{
						"type":        "number",
						"description": "Confidence score (0.0 to 1.0)",
					},
				},
				"required": []string{"id"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				ID         string  `json:"id"`
				Status     string  `json:"status"`
				Confidence float64 `json:"confidence"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			onUpdateNode(params.ID, params.Status, params.Confidence)
			return fmt.Sprintf("CausalNode updated: %s (Status: %s, Confidence: %.2f)", params.ID, params.Status, params.Confidence), nil
		},
	})

	// Tool 3: cg_add_edge
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "cg_add_edge",
			Description: "Create a relationship between two nodes in the Causal Evidence Graph. This represents causal links like support, contradiction, or revelation.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source_id": map[string]interface{}{
						"type":        "string",
						"description": "ID of the source node",
					},
					"target_id": map[string]interface{}{
						"type":        "string",
						"description": "ID of the target node",
					},
					"label": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"SUPPORTS", "CONTRADICTS", "REVEALS", "REQUIRES", "BLOCKS"},
						"description": "The nature of the relationship",
					},
				},
				"required": []string{"source_id", "target_id", "label"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				SourceID string `json:"source_id"`
				TargetID string `json:"target_id"`
				Label    string `json:"label"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			onAddEdge(params.SourceID, params.TargetID, params.Label)
			return fmt.Sprintf("CausalEdge added: %s --[%s]--> %s", params.SourceID, params.Label, params.TargetID), nil
		},
	})
}
