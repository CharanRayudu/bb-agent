package agent

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/bb-agent/mirage/internal/models"
)

func ensureAttackGraph(brain *Brain) *models.CausalGraph {
	if brain.CausalGraph == nil {
		brain.CausalGraph = &models.CausalGraph{
			Nodes: make(map[string]*models.CausalNode),
			Edges: []models.CausalEdge{},
		}
	}
	if brain.CausalGraph.Nodes == nil {
		brain.CausalGraph.Nodes = make(map[string]*models.CausalNode)
	}
	return brain.CausalGraph
}

func upsertAttackGraphNode(brain *Brain, id, nodeType, description, status string, confidence float64) {
	if strings.TrimSpace(id) == "" {
		return
	}
	graph := ensureAttackGraph(brain)
	if existing, ok := graph.Nodes[id]; ok {
		if strings.TrimSpace(nodeType) != "" {
			existing.NodeType = nodeType
		}
		if strings.TrimSpace(description) != "" {
			existing.Description = description
		}
		if strings.TrimSpace(status) != "" {
			existing.Status = status
		}
		if confidence > existing.Confidence {
			existing.Confidence = confidence
		}
		return
	}

	graph.Nodes[id] = &models.CausalNode{
		ID:          id,
		NodeType:    nodeType,
		Description: description,
		Confidence:  confidence,
		Status:      status,
	}
}

func addAttackGraphEdge(brain *Brain, sourceID, targetID, label string) {
	if strings.TrimSpace(sourceID) == "" || strings.TrimSpace(targetID) == "" || strings.TrimSpace(label) == "" {
		return
	}
	graph := ensureAttackGraph(brain)
	for _, edge := range graph.Edges {
		if edge.SourceID == sourceID && edge.TargetID == targetID && edge.Label == label {
			return
		}
	}
	graph.Edges = append(graph.Edges, models.CausalEdge{
		SourceID: sourceID,
		TargetID: targetID,
		Label:    label,
	})
}

func attackGraphNodeID(prefix, raw string) string {
	normalized := normalizeBrainNote(raw)
	if normalized == "" {
		normalized = strings.TrimSpace(raw)
	}
	if normalized == "" {
		normalized = "node"
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(normalized))
	return fmt.Sprintf("%s:%s:%08x", prefix, slugifyAttackGraph(normalized), hasher.Sum32())
}

func slugifyAttackGraph(raw string) string {
	lower := strings.ToLower(raw)
	var b strings.Builder
	lastDash := false
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}

	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "node"
	}
	if len(slug) > 32 {
		slug = strings.Trim(slug[:32], "-")
	}
	if slug == "" {
		return "node"
	}
	return slug
}

func seedAttackGraphTarget(brain *Brain, target string) string {
	targetID := attackGraphNodeID("target", target)
	upsertAttackGraphNode(brain, targetID, "Fact", "In-scope target: "+strings.TrimSpace(target), "CONFIRMED", 1.0)
	return targetID
}

func updateLeadAttackGraph(brain *Brain, target, note string) {
	normalized := normalizeBrainNote(note)
	if normalized == "" {
		return
	}
	targetID := seedAttackGraphTarget(brain, target)
	leadID := attackGraphNodeID("lead", normalized)
	upsertAttackGraphNode(brain, leadID, "Fact", normalized, "PENDING", 0.35)
	addAttackGraphEdge(brain, targetID, leadID, "REVEALS")
}

func updateAuthAttackGraph(brain *Brain, target string, auth *AuthState) {
	if auth == nil {
		return
	}
	summary := buildAuthContextSummary(auth)
	if strings.TrimSpace(summary) == "" {
		summary = "Authentication context captured for the target."
	}
	targetID := seedAttackGraphTarget(brain, target)
	authID := attackGraphNodeID("auth", target)
	upsertAttackGraphNode(brain, authID, "Fact", summary, "CONFIRMED", 0.95)
	addAttackGraphEdge(brain, targetID, authID, "REVEALS")
}

func updateHypothesisAttackGraph(brain *Brain, baseTarget string, spec SwarmAgentSpec) {
	spec = enrichSwarmAgentSpec(baseTarget, spec, nil)

	targetID := seedAttackGraphTarget(brain, baseTarget)
	hypothesisID := attackGraphNodeID("hypothesis", dispatchFingerprint(spec, baseTarget))
	upsertAttackGraphNode(brain, hypothesisID, "Hypothesis", spec.Hypothesis, "PENDING", 0.55)
	addAttackGraphEdge(brain, targetID, hypothesisID, "REVEALS")

	if normalized := normalizeBrainNote(spec.Context); normalized != "" {
		leadID := attackGraphNodeID("lead", normalized)
		upsertAttackGraphNode(brain, leadID, "Fact", normalized, "PENDING", 0.4)
		addAttackGraphEdge(brain, targetID, leadID, "REVEALS")
		addAttackGraphEdge(brain, leadID, hypothesisID, "SUPPORTS")
	}

	if spec.RequiresAuth && strings.TrimSpace(spec.AuthContext) != "" {
		authID := attackGraphNodeID("auth", baseTarget)
		upsertAttackGraphNode(brain, authID, "Fact", spec.AuthContext, "CONFIRMED", 0.95)
		addAttackGraphEdge(brain, targetID, authID, "REVEALS")
		addAttackGraphEdge(brain, hypothesisID, authID, "REQUIRES")
	}
}

func updateFindingAttackGraph(brain *Brain, baseTarget string, f *Finding) {
	if f == nil {
		return
	}

	targetID := seedAttackGraphTarget(brain, baseTarget)
	proof, _ := classifyFindingProof(f)
	description := fmt.Sprintf("%s on %s", strings.TrimSpace(f.Type), strings.TrimSpace(f.URL))
	if f.Parameter != "" {
		description += fmt.Sprintf(" (parameter: %s)", f.Parameter)
	}
	if proof != proofClassNone {
		description += fmt.Sprintf(" [%s proof]", string(proof))
	}

	vulnID := attackGraphNodeID("vulnerability", findingFingerprint(f))
	confidence := f.Confidence
	if confidence < 0.8 {
		confidence = 0.9
	}
	upsertAttackGraphNode(brain, vulnID, "Vulnerability", description, "CONFIRMED", confidence)
	addAttackGraphEdge(brain, targetID, vulnID, "REVEALS")

	supportingSpec := enrichSwarmAgentSpec(baseTarget, SwarmAgentSpec{
		Type:     f.Type,
		Target:   f.URL,
		Context:  description,
		Priority: f.Severity,
	}, nil)
	hypothesisID := attackGraphNodeID("hypothesis", dispatchFingerprint(supportingSpec, baseTarget))
	upsertAttackGraphNode(brain, hypothesisID, "Hypothesis", supportingSpec.Hypothesis, "CONFIRMED", 0.8)
	addAttackGraphEdge(brain, hypothesisID, vulnID, "REVEALS")
}
