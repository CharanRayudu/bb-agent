package agent

import (
	"testing"

	"github.com/bb-agent/mirage/internal/models"
)

func TestCloneBrainRoundTripsAuthGraphAndFindings(t *testing.T) {
	brain := &Brain{
		Leads:      []string{"lead-1"},
		Exclusions: []string{"exclude-1"},
		Auth: &AuthState{
			Cookies:    map[string]string{"session": "abc"},
			Headers:    map[string]string{"Authorization": "Bearer token"},
			LoginURL:   "https://example.com/login",
			AuthMethod: "bearer",
			Notes:      []string{"authenticated workflow"},
		},
		CausalGraph: ensureAttackGraph(&Brain{}),
		Findings: []*Finding{{
			Type:     "IDOR",
			URL:      "https://example.com/api/users/2",
			Severity: "high",
			Evidence: map[string]interface{}{
				"request":  "GET /api/users/2 HTTP/1.1",
				"response": "200 OK\nother user's record",
			},
		}},
	}
	brain.CausalGraph.Nodes["node-1"] = &models.CausalNode{ID: "node-1", NodeType: "Hypothesis", Description: "test"}
	brain.CausalGraph.Edges = append(brain.CausalGraph.Edges, models.CausalEdge{SourceID: "target", TargetID: "node-1", Label: "REVEALS"})

	clone := cloneBrain(brain)
	if clone == nil {
		t.Fatal("expected clone to be created")
	}
	if clone == brain {
		t.Fatal("expected deep clone, got original pointer")
	}
	if clone.Auth == nil || clone.Auth.Cookies["session"] != "abc" {
		t.Fatalf("expected auth state to survive clone, got %#v", clone.Auth)
	}
	if clone.CausalGraph == nil || len(clone.CausalGraph.Nodes) != 1 || len(clone.CausalGraph.Edges) != 1 {
		t.Fatalf("expected causal graph to survive clone, got %#v", clone.CausalGraph)
	}
	if len(clone.Findings) != 1 || clone.Findings[0].Evidence["response"] == nil {
		t.Fatalf("expected findings to survive clone, got %#v", clone.Findings)
	}
}

func TestBuildBrainSnapshotSummaryIncludesCountsAndProofClasses(t *testing.T) {
	brain := &Brain{
		Leads:      []string{"lead-a", "lead-b"},
		Exclusions: []string{"exclude-a"},
		Auth:       &AuthState{AuthMethod: "cookie", LoginURL: "https://example.com/login"},
		CausalGraph: &models.CausalGraph{
			Nodes: map[string]*models.CausalNode{
				"target": {ID: "target"},
				"hyp":    {ID: "hyp"},
			},
			Edges: []models.CausalEdge{{SourceID: "target", TargetID: "hyp", Label: "REVEALS"}},
		},
		Findings: []*Finding{{
			Type:     "XSS",
			URL:      "https://example.com/profile",
			Severity: "medium",
			Evidence: map[string]interface{}{
				"screenshot": "stored-xss.png",
			},
		}},
	}

	summary := buildBrainSnapshotSummary(brain)
	if summary["lead_count"] != 2 {
		t.Fatalf("expected 2 leads, got %#v", summary["lead_count"])
	}
	if summary["finding_count"] != 1 {
		t.Fatalf("expected 1 finding, got %#v", summary["finding_count"])
	}
	if summary["auth_present"] != true || summary["auth_method"] != "cookie" {
		t.Fatalf("expected auth metadata in summary, got %#v", summary)
	}
	proofClasses, ok := summary["proof_classes"].(map[string]int)
	if !ok {
		t.Fatalf("expected proof class counts, got %#v", summary["proof_classes"])
	}
	if proofClasses[string(proofClassBrowser)] != 1 {
		t.Fatalf("expected browser proof count, got %#v", proofClasses)
	}
}

func TestBrainFromSnapshotStateRestoresStructuredBrain(t *testing.T) {
	original := &Brain{
		Leads:        []string{"admin panel"},
		PivotContext: "credential pivot",
		Auth:         &AuthState{AuthMethod: "cookie"},
		Findings: []*Finding{{
			Type:     "SQLi",
			URL:      "https://example.com/search",
			Severity: "high",
			Evidence: map[string]interface{}{
				"request":  "GET /search?q=1%27 HTTP/1.1",
				"response": "500 Internal Server Error",
			},
		}},
	}

	state := brainSnapshotState(original)
	restored, err := brainFromSnapshotState(state)
	if err != nil {
		t.Fatalf("expected state to round trip, got error %v", err)
	}
	if len(restored.Leads) != 1 || restored.Leads[0] != "admin panel" {
		t.Fatalf("expected leads to round trip, got %#v", restored.Leads)
	}
	if restored.Auth == nil || restored.Auth.AuthMethod != "cookie" {
		t.Fatalf("expected auth to round trip, got %#v", restored.Auth)
	}
	if len(restored.Findings) != 1 || restored.Findings[0].Type != "SQLi" {
		t.Fatalf("expected findings to round trip, got %#v", restored.Findings)
	}
}
