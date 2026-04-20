// Package knowledge provides a persistent knowledge graph for cross-session
// learning. It tracks relationships between hosts, services, vulnerabilities,
// techniques, and payloads, enabling the agent to learn from past engagements.
//
// The graph can be backed by Neo4j (production) or an in-memory store (dev/test).
package knowledge

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// NodeType classifies entities in the knowledge graph.
type NodeType string

const (
	NodeHost          NodeType = "Host"
	NodeService       NodeType = "Service"
	NodeVulnerability NodeType = "Vulnerability"
	NodeTechnique     NodeType = "Technique"
	NodePayload       NodeType = "Payload"
	NodeTechStack     NodeType = "TechStack"
)

// EdgeType classifies relationships in the knowledge graph.
type EdgeType string

const (
	EdgeRunsOn       EdgeType = "RUNS_ON"
	EdgeVulnTo       EdgeType = "VULNERABLE_TO"
	EdgeExploitedBy  EdgeType = "EXPLOITED_BY"
	EdgeSimilarTo    EdgeType = "SIMILAR_TO"
	EdgeLeadsTo      EdgeType = "LEADS_TO"
	EdgeUsesTech     EdgeType = "USES_TECH"
	EdgeTestedWith   EdgeType = "TESTED_WITH"
	EdgeDiscoveredBy EdgeType = "DISCOVERED_BY"
)

// KGNode is a node in the knowledge graph.
type KGNode struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	FlowID     string                 `json:"flow_id,omitempty"`
}

// KGEdge is a directed edge in the knowledge graph.
type KGEdge struct {
	ID         string                 `json:"id"`
	SourceID   string                 `json:"source_id"`
	TargetID   string                 `json:"target_id"`
	Type       EdgeType               `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

// Graph defines the interface for knowledge graph operations.
// Implementations can use Neo4j, PostgreSQL, or in-memory stores.
type Graph interface {
	// Node operations
	AddNode(node *KGNode) error
	GetNode(id string) (*KGNode, error)
	UpdateNode(id string, properties map[string]interface{}) error
	FindNodes(nodeType NodeType, filters map[string]interface{}) ([]*KGNode, error)

	// Edge operations
	AddEdge(edge *KGEdge) error
	GetEdges(nodeID string, edgeType EdgeType) ([]*KGEdge, error)

	// Query operations
	FindSimilarTargets(techStack string) ([]*KGNode, error)
	GetAttackChains(hostID string) ([][]*KGNode, error)
	GetVulnerabilities(hostID string) ([]*KGNode, error)
	GetEffectivePayloads(techStack, vulnType string) ([]*KGNode, error)

	// Export operations (for API serialization)
	AllNodes() []*KGNode
	AllEdges() []*KGEdge

	// Lifecycle
	Close() error
}

// InMemoryGraph is a development/testing implementation of the knowledge graph.
type InMemoryGraph struct {
	nodes map[string]*KGNode
	edges []*KGEdge
	mu    sync.RWMutex
}

// NewInMemoryGraph creates an in-memory knowledge graph.
func NewInMemoryGraph() *InMemoryGraph {
	return &InMemoryGraph{
		nodes: make(map[string]*KGNode),
		edges: make([]*KGEdge, 0),
	}
}

func (g *InMemoryGraph) AllNodes() []*KGNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*KGNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

func (g *InMemoryGraph) AllEdges() []*KGEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*KGEdge, len(g.edges))
	copy(out, g.edges)
	return out
}

func (g *InMemoryGraph) AddNode(node *KGNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if node.ID == "" {
		node.ID = uuid.New().String()
	}
	now := time.Now()
	if node.CreatedAt.IsZero() {
		node.CreatedAt = now
	}
	node.UpdatedAt = now
	if node.Properties == nil {
		node.Properties = make(map[string]interface{})
	}

	g.nodes[node.ID] = node
	return nil
}

func (g *InMemoryGraph) GetNode(id string) (*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	if !ok {
		return nil, fmt.Errorf("node %s not found", id)
	}
	return node, nil
}

func (g *InMemoryGraph) UpdateNode(id string, properties map[string]interface{}) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, ok := g.nodes[id]
	if !ok {
		return fmt.Errorf("node %s not found", id)
	}

	for k, v := range properties {
		node.Properties[k] = v
	}
	node.UpdatedAt = time.Now()
	return nil
}

func (g *InMemoryGraph) FindNodes(nodeType NodeType, filters map[string]interface{}) ([]*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*KGNode
	for _, node := range g.nodes {
		if node.Type != nodeType {
			continue
		}
		match := true
		for k, v := range filters {
			if nv, ok := node.Properties[k]; !ok || fmt.Sprint(nv) != fmt.Sprint(v) {
				match = false
				break
			}
		}
		if match {
			results = append(results, node)
		}
	}
	return results, nil
}

func (g *InMemoryGraph) AddEdge(edge *KGEdge) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if edge.ID == "" {
		edge.ID = uuid.New().String()
	}
	if edge.CreatedAt.IsZero() {
		edge.CreatedAt = time.Now()
	}

	// Dedup
	for _, existing := range g.edges {
		if existing.SourceID == edge.SourceID && existing.TargetID == edge.TargetID && existing.Type == edge.Type {
			return nil
		}
	}

	g.edges = append(g.edges, edge)
	return nil
}

func (g *InMemoryGraph) GetEdges(nodeID string, edgeType EdgeType) ([]*KGEdge, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*KGEdge
	for _, edge := range g.edges {
		if (edge.SourceID == nodeID || edge.TargetID == nodeID) && edge.Type == edgeType {
			results = append(results, edge)
		}
	}
	return results, nil
}

func (g *InMemoryGraph) FindSimilarTargets(techStack string) ([]*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	lower := strings.ToLower(techStack)
	var results []*KGNode
	for _, node := range g.nodes {
		if node.Type != NodeHost {
			continue
		}
		if ts, ok := node.Properties["tech_stack"].(string); ok {
			if strings.Contains(strings.ToLower(ts), lower) {
				results = append(results, node)
			}
		}
	}
	return results, nil
}

func (g *InMemoryGraph) GetAttackChains(hostID string) ([][]*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Find all vulnerabilities connected to this host
	var chains [][]*KGNode
	for _, edge := range g.edges {
		if edge.SourceID == hostID && edge.Type == EdgeVulnTo {
			vulnNode, ok := g.nodes[edge.TargetID]
			if !ok {
				continue
			}
			chain := []*KGNode{g.nodes[hostID], vulnNode}

			// Follow EXPLOITED_BY edges
			for _, e2 := range g.edges {
				if e2.SourceID == vulnNode.ID && e2.Type == EdgeExploitedBy {
					if techNode, ok := g.nodes[e2.TargetID]; ok {
						chain = append(chain, techNode)
					}
				}
			}
			chains = append(chains, chain)
		}
	}
	return chains, nil
}

func (g *InMemoryGraph) GetVulnerabilities(hostID string) ([]*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*KGNode
	for _, edge := range g.edges {
		if edge.SourceID == hostID && edge.Type == EdgeVulnTo {
			if node, ok := g.nodes[edge.TargetID]; ok {
				results = append(results, node)
			}
		}
	}
	return results, nil
}

func (g *InMemoryGraph) GetEffectivePayloads(techStack, vulnType string) ([]*KGNode, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*KGNode
	for _, node := range g.nodes {
		if node.Type != NodePayload {
			continue
		}
		props := node.Properties
		if vt, ok := props["vuln_type"].(string); ok && strings.EqualFold(vt, vulnType) {
			if ts, ok := props["tech_stack"].(string); ok && strings.Contains(strings.ToLower(ts), strings.ToLower(techStack)) {
				results = append(results, node)
			}
		}
	}
	return results, nil
}

func (g *InMemoryGraph) Close() error {
	return nil
}

// --- Helper: Record a vulnerability finding in the knowledge graph ---

// RecordFinding persists a confirmed vulnerability and its relationships.
func RecordFinding(g Graph, hostID, flowID string, vulnType, url, payload, techStack string, confidence float64) error {
	vulnID := uuid.New().String()
	if err := g.AddNode(&KGNode{
		ID:   vulnID,
		Type: NodeVulnerability,
		Label: fmt.Sprintf("%s on %s", vulnType, url),
		Properties: map[string]interface{}{
			"vuln_type":  vulnType,
			"url":        url,
			"confidence": confidence,
			"tech_stack": techStack,
		},
		FlowID: flowID,
	}); err != nil {
		return err
	}

	if err := g.AddEdge(&KGEdge{
		SourceID: hostID,
		TargetID: vulnID,
		Type:     EdgeVulnTo,
	}); err != nil {
		return err
	}

	if payload != "" {
		payloadID := uuid.New().String()
		if err := g.AddNode(&KGNode{
			ID:   payloadID,
			Type: NodePayload,
			Label: truncateLabel(payload, 100),
			Properties: map[string]interface{}{
				"payload":    payload,
				"vuln_type":  vulnType,
				"tech_stack": techStack,
				"success":    true,
			},
			FlowID: flowID,
		}); err != nil {
			return err
		}

		if err := g.AddEdge(&KGEdge{
			SourceID: vulnID,
			TargetID: payloadID,
			Type:     EdgeExploitedBy,
		}); err != nil {
			return err
		}
	}

	return nil
}

// RecordHost creates or updates a host node in the knowledge graph.
func RecordHost(g Graph, target, techStack, flowID string) (string, error) {
	hostID := "host:" + strings.ReplaceAll(target, "://", "-")
	hostID = strings.ReplaceAll(hostID, "/", "-")

	existing, err := g.GetNode(hostID)
	if err == nil && existing != nil {
		return hostID, g.UpdateNode(hostID, map[string]interface{}{
			"tech_stack":  techStack,
			"last_scanned": time.Now().Format(time.RFC3339),
		})
	}

	return hostID, g.AddNode(&KGNode{
		ID:   hostID,
		Type: NodeHost,
		Label: target,
		Properties: map[string]interface{}{
			"target":     target,
			"tech_stack": techStack,
		},
		FlowID: flowID,
	})
}

func truncateLabel(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
