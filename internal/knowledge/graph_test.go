package knowledge_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/knowledge"
)

func newGraph() *knowledge.InMemoryGraph {
	return knowledge.NewInMemoryGraph()
}

// ── AddNode / GetNode ─────────────────────────────────────────────────────────

func TestAddNode_AutoID(t *testing.T) {
	g := newGraph()
	n := &knowledge.KGNode{Type: knowledge.NodeHost, Label: "example.com"}
	if err := g.AddNode(n); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if n.ID == "" {
		t.Error("ID should be auto-assigned")
	}
	if n.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestAddNode_WithExplicitID(t *testing.T) {
	g := newGraph()
	n := &knowledge.KGNode{ID: "host:example.com", Type: knowledge.NodeHost, Label: "example.com"}
	if err := g.AddNode(n); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	got, err := g.GetNode("host:example.com")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Label != "example.com" {
		t.Errorf("Label = %q, want example.com", got.Label)
	}
}

func TestGetNode_NotFound(t *testing.T) {
	g := newGraph()
	_, err := g.GetNode("ghost")
	if err == nil {
		t.Error("expected error for nonexistent node")
	}
}

// ── UpdateNode ────────────────────────────────────────────────────────────────

func TestUpdateNode(t *testing.T) {
	g := newGraph()
	n := &knowledge.KGNode{ID: "n1", Type: knowledge.NodeHost, Label: "host"}
	g.AddNode(n) //nolint
	if err := g.UpdateNode("n1", map[string]interface{}{"tech_stack": "Django"}); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	got, _ := g.GetNode("n1")
	if got.Properties["tech_stack"] != "Django" {
		t.Errorf("tech_stack = %v, want Django", got.Properties["tech_stack"])
	}
}

func TestUpdateNode_NotFound(t *testing.T) {
	g := newGraph()
	if err := g.UpdateNode("ghost", map[string]interface{}{"x": 1}); err == nil {
		t.Error("expected error for nonexistent node")
	}
}

// ── FindNodes ─────────────────────────────────────────────────────────────────

func TestFindNodes_ByType(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{Type: knowledge.NodeHost, Label: "h1"})            //nolint
	g.AddNode(&knowledge.KGNode{Type: knowledge.NodeVulnerability, Label: "vuln"}) //nolint

	hosts, err := g.FindNodes(knowledge.NodeHost, nil)
	if err != nil {
		t.Fatalf("FindNodes: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("got %d hosts, want 1", len(hosts))
	}
}

func TestFindNodes_WithFilter(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "n1", Type: knowledge.NodeHost, Label: "h1", Properties: map[string]interface{}{"env": "prod"}})    //nolint
	g.AddNode(&knowledge.KGNode{ID: "n2", Type: knowledge.NodeHost, Label: "h2", Properties: map[string]interface{}{"env": "staging"}}) //nolint

	res, _ := g.FindNodes(knowledge.NodeHost, map[string]interface{}{"env": "prod"})
	if len(res) != 1 || res[0].ID != "n1" {
		t.Errorf("filter by env=prod: got %d results", len(res))
	}
}

// ── AddEdge / GetEdges ────────────────────────────────────────────────────────

func TestAddEdge_Dedup(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "a", Type: knowledge.NodeHost, Label: "a"})             //nolint
	g.AddNode(&knowledge.KGNode{ID: "b", Type: knowledge.NodeVulnerability, Label: "vuln"}) //nolint

	e := &knowledge.KGEdge{SourceID: "a", TargetID: "b", Type: knowledge.EdgeVulnTo}
	g.AddEdge(e) //nolint
	g.AddEdge(e) //nolint — duplicate should be ignored

	edges, err := g.GetEdges("a", knowledge.EdgeVulnTo)
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge after dedup, got %d", len(edges))
	}
}

func TestAddEdge_AutoID(t *testing.T) {
	g := newGraph()
	e := &knowledge.KGEdge{SourceID: "s", TargetID: "t", Type: knowledge.EdgeLeadsTo}
	g.AddEdge(e) //nolint
	if e.ID == "" {
		t.Error("edge ID should be auto-assigned")
	}
}

func TestGetEdges_BothDirections(t *testing.T) {
	g := newGraph()
	e := &knowledge.KGEdge{ID: "e1", SourceID: "a", TargetID: "b", Type: knowledge.EdgeRunsOn}
	g.AddEdge(e) //nolint

	// Should return when querying from source
	edges, _ := g.GetEdges("a", knowledge.EdgeRunsOn)
	if len(edges) != 1 {
		t.Errorf("GetEdges from source: got %d, want 1", len(edges))
	}
	// Should return when querying from target
	edges, _ = g.GetEdges("b", knowledge.EdgeRunsOn)
	if len(edges) != 1 {
		t.Errorf("GetEdges from target: got %d, want 1", len(edges))
	}
}

// ── FindSimilarTargets ────────────────────────────────────────────────────────

func TestFindSimilarTargets(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "h1", Type: knowledge.NodeHost, Label: "h1", Properties: map[string]interface{}{"tech_stack": "Django Python"}}) //nolint
	g.AddNode(&knowledge.KGNode{ID: "h2", Type: knowledge.NodeHost, Label: "h2", Properties: map[string]interface{}{"tech_stack": "Rails Ruby"}})    //nolint
	g.AddNode(&knowledge.KGNode{ID: "h3", Type: knowledge.NodeHost, Label: "h3", Properties: map[string]interface{}{"tech_stack": "Django REST"}})   //nolint

	res, err := g.FindSimilarTargets("django")
	if err != nil {
		t.Fatalf("FindSimilarTargets: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("got %d django targets, want 2", len(res))
	}
}

// ── GetAttackChains ───────────────────────────────────────────────────────────

func TestGetAttackChains(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "host1", Type: knowledge.NodeHost, Label: "target"})        //nolint
	g.AddNode(&knowledge.KGNode{ID: "vuln1", Type: knowledge.NodeVulnerability, Label: "sqli"}) //nolint
	g.AddNode(&knowledge.KGNode{ID: "tech1", Type: knowledge.NodeTechnique, Label: "union"})    //nolint

	g.AddEdge(&knowledge.KGEdge{SourceID: "host1", TargetID: "vuln1", Type: knowledge.EdgeVulnTo})      //nolint
	g.AddEdge(&knowledge.KGEdge{SourceID: "vuln1", TargetID: "tech1", Type: knowledge.EdgeExploitedBy}) //nolint

	chains, err := g.GetAttackChains("host1")
	if err != nil {
		t.Fatalf("GetAttackChains: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("got %d chains, want 1", len(chains))
	}
	if len(chains[0]) < 2 {
		t.Errorf("chain length = %d, want ≥2", len(chains[0]))
	}
}

func TestGetAttackChains_NoVulns(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "clean-host", Type: knowledge.NodeHost, Label: "safe"}) //nolint

	chains, err := g.GetAttackChains("clean-host")
	if err != nil {
		t.Fatalf("GetAttackChains: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains for host with no vulns, got %d", len(chains))
	}
}

// ── GetVulnerabilities ────────────────────────────────────────────────────────

func TestGetVulnerabilities(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{ID: "h", Type: knowledge.NodeHost, Label: "h"})              //nolint
	g.AddNode(&knowledge.KGNode{ID: "v1", Type: knowledge.NodeVulnerability, Label: "xss"})  //nolint
	g.AddNode(&knowledge.KGNode{ID: "v2", Type: knowledge.NodeVulnerability, Label: "sqli"}) //nolint

	g.AddEdge(&knowledge.KGEdge{SourceID: "h", TargetID: "v1", Type: knowledge.EdgeVulnTo}) //nolint
	g.AddEdge(&knowledge.KGEdge{SourceID: "h", TargetID: "v2", Type: knowledge.EdgeVulnTo}) //nolint

	vulns, err := g.GetVulnerabilities("h")
	if err != nil {
		t.Fatalf("GetVulnerabilities: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("got %d vulns, want 2", len(vulns))
	}
}

// ── GetEffectivePayloads ──────────────────────────────────────────────────────

func TestGetEffectivePayloads(t *testing.T) {
	g := newGraph()
	g.AddNode(&knowledge.KGNode{
		ID: "p1", Type: knowledge.NodePayload, Label: "' OR 1=1--",
		Properties: map[string]interface{}{"vuln_type": "SQLi", "tech_stack": "MySQL"},
	}) //nolint
	g.AddNode(&knowledge.KGNode{
		ID: "p2", Type: knowledge.NodePayload, Label: "<script>",
		Properties: map[string]interface{}{"vuln_type": "XSS", "tech_stack": "JavaScript"},
	}) //nolint

	res, err := g.GetEffectivePayloads("MySQL", "SQLi")
	if err != nil {
		t.Fatalf("GetEffectivePayloads: %v", err)
	}
	if len(res) != 1 || res[0].ID != "p1" {
		t.Errorf("got %d results, want 1 with id p1", len(res))
	}
}

// ── AllNodes / AllEdges ───────────────────────────────────────────────────────

func TestAllNodesAndEdges_Empty(t *testing.T) {
	g := newGraph()
	if nodes := g.AllNodes(); nodes == nil {
		t.Error("AllNodes should return non-nil slice")
	}
	if edges := g.AllEdges(); edges == nil {
		t.Error("AllEdges should return non-nil slice")
	}
}

func TestAllNodes(t *testing.T) {
	g := newGraph()
	for i := 0; i < 5; i++ {
		g.AddNode(&knowledge.KGNode{Type: knowledge.NodeHost, Label: "h"}) //nolint
	}
	nodes := g.AllNodes()
	if len(nodes) != 5 {
		t.Errorf("AllNodes = %d, want 5", len(nodes))
	}
}

// ── RecordHost / RecordFinding ────────────────────────────────────────────────

func TestRecordHost(t *testing.T) {
	g := newGraph()
	hostID, err := knowledge.RecordHost(g, "https://target.example.com", "Django", "flow-1")
	if err != nil {
		t.Fatalf("RecordHost: %v", err)
	}
	if hostID == "" {
		t.Error("expected non-empty hostID")
	}

	// Second call should update, not duplicate
	hostID2, err := knowledge.RecordHost(g, "https://target.example.com", "Django 3.2", "flow-2")
	if err != nil {
		t.Fatalf("RecordHost (update): %v", err)
	}
	if hostID != hostID2 {
		t.Errorf("hostID changed on update: %s → %s", hostID, hostID2)
	}

	nodes := g.AllNodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 host node, got %d", len(nodes))
	}
}

func TestRecordFinding(t *testing.T) {
	g := newGraph()
	hostID, _ := knowledge.RecordHost(g, "https://victim.com", "PHP", "f1")

	err := knowledge.RecordFinding(g, hostID, "f1", "SQLi", "https://victim.com/search?q=", "' OR 1=1", "PHP", 0.95)
	if err != nil {
		t.Fatalf("RecordFinding: %v", err)
	}

	// Should have host node + vuln node + payload node
	nodes := g.AllNodes()
	if len(nodes) < 3 {
		t.Errorf("expected ≥3 nodes (host, vuln, payload), got %d", len(nodes))
	}

	edges := g.AllEdges()
	if len(edges) < 2 {
		t.Errorf("expected ≥2 edges (vulnTo, exploitedBy), got %d", len(edges))
	}
}

func TestRecordFinding_NoPayload(t *testing.T) {
	g := newGraph()
	hostID, _ := knowledge.RecordHost(g, "https://api.example.com", "Go", "f2")

	err := knowledge.RecordFinding(g, hostID, "f2", "SSRF", "https://api.example.com/proxy", "", "Go", 0.8)
	if err != nil {
		t.Fatalf("RecordFinding (no payload): %v", err)
	}

	// host + vuln, no payload node
	nodes := g.AllNodes()
	if len(nodes) < 2 {
		t.Errorf("expected ≥2 nodes, got %d", len(nodes))
	}
}

func TestClose(t *testing.T) {
	g := newGraph()
	if err := g.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
