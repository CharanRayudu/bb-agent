package agent

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

func cloneBrain(brain *Brain) *Brain {
	if brain == nil {
		return nil
	}
	raw, err := json.Marshal(brain)
	if err != nil {
		return &Brain{}
	}
	var clone Brain
	if err := json.Unmarshal(raw, &clone); err != nil {
		return &Brain{}
	}
	return &clone
}

func brainSnapshotState(brain *Brain) map[string]any {
	if brain == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(brain)
	if err != nil {
		return map[string]any{}
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		return map[string]any{}
	}
	if state == nil {
		return map[string]any{}
	}
	return state
}

func brainFromSnapshotState(state map[string]any) (Brain, error) {
	if len(state) == 0 {
		return Brain{}, nil
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return Brain{}, err
	}
	var brain Brain
	if err := json.Unmarshal(raw, &brain); err != nil {
		return Brain{}, err
	}
	return brain, nil
}

func buildBrainSnapshotSummary(brain *Brain) map[string]any {
	summary := map[string]any{
		"lead_count":          0,
		"finding_count":       0,
		"hallucination_count": 0,
		"defence_count":       0,
		"exclusion_count":     0,
		"auth_present":        false,
		"graph_nodes":         0,
		"graph_edges":         0,
		"proof_classes":       map[string]int{},
	}
	if brain == nil {
		return summary
	}

	summary["lead_count"] = len(brain.Leads)
	summary["finding_count"] = len(brain.Findings)
	summary["hallucination_count"] = len(brain.HallucinationBin)
	summary["defence_count"] = len(brain.KnownDefences)
	summary["exclusion_count"] = len(brain.Exclusions)
	if strings.TrimSpace(brain.PivotContext) != "" {
		summary["pivot_present"] = true
	}
	if brain.Tech != nil {
		if strings.TrimSpace(brain.Tech.Lang) != "" {
			summary["tech_lang"] = brain.Tech.Lang
		}
		if strings.TrimSpace(brain.Tech.DB) != "" {
			summary["tech_db"] = brain.Tech.DB
		}
	}
	if brain.Auth != nil {
		summary["auth_present"] = true
		if strings.TrimSpace(brain.Auth.AuthMethod) != "" {
			summary["auth_method"] = brain.Auth.AuthMethod
		}
		if strings.TrimSpace(brain.Auth.LoginURL) != "" {
			summary["auth_login_url"] = brain.Auth.LoginURL
		}
	}
	if brain.CausalGraph != nil {
		summary["graph_nodes"] = len(brain.CausalGraph.Nodes)
		summary["graph_edges"] = len(brain.CausalGraph.Edges)
	}

	proofClasses := map[string]int{}
	for _, finding := range brain.Findings {
		proof, _ := classifyFindingProof(finding)
		key := string(proof)
		if key == "" {
			key = "unclassified"
		}
		proofClasses[key]++
	}
	summary["proof_classes"] = proofClasses

	return summary
}

func (o *Orchestrator) persistBrainSnapshot(flowID uuid.UUID, taskID *uuid.UUID, stage string, brain *Brain) {
	if o == nil || o.queries == nil || brain == nil {
		return
	}
	snapshot := &models.BrainSnapshot{
		FlowID:  flowID,
		TaskID:  taskID,
		Stage:   strings.TrimSpace(stage),
		State:   brainSnapshotState(brain),
		Summary: buildBrainSnapshotSummary(brain),
	}
	if snapshot.Stage == "" {
		snapshot.Stage = "runtime"
	}
	if err := o.queries.UpsertBrainSnapshot(snapshot); err != nil {
		log.Printf("[brain] failed to persist brain snapshot for flow %s at %s: %v", flowID, snapshot.Stage, err)
	}
}

func (o *Orchestrator) restoreBrainSnapshot(flowID uuid.UUID) (Brain, bool) {
	if o == nil || o.queries == nil {
		return Brain{}, false
	}
	snapshot, err := o.queries.GetLatestBrainSnapshot(flowID)
	if err != nil {
		log.Printf("[brain] failed to restore brain snapshot for flow %s: %v", flowID, err)
		return Brain{}, false
	}
	if snapshot == nil {
		return Brain{}, false
	}
	brain, err := brainFromSnapshotState(snapshot.State)
	if err != nil {
		log.Printf("[brain] failed to decode brain snapshot for flow %s: %v", flowID, err)
		return Brain{}, false
	}
	return brain, true
}
