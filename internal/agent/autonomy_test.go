package agent

import (
	"strings"
	"testing"
)

func TestMergeAuthContextFromNotePreservesStructuredState(t *testing.T) {
	var auth *AuthState
	state := ensureAuthState(&auth)
	changed := mergeAuthContextFromNote(state, "Set-Cookie: session=abc123; HttpOnly Authorization: Bearer token-value-12345 admin:supersecret https://example.com/login")
	if !changed {
		t.Fatal("expected auth state to change")
	}
	if state.Cookies["session"] != "abc123" {
		t.Fatalf("expected session cookie to be captured, got %+v", state.Cookies)
	}
	if state.Headers["Authorization"] != "Bearer token-value-12345" {
		t.Fatalf("expected bearer token to be captured, got %+v", state.Headers)
	}
	if state.Credentials["admin"] != "supersecret" {
		t.Fatalf("expected credentials to be captured, got %+v", state.Credentials)
	}
	if state.LoginURL != "https://example.com/login" {
		t.Fatalf("expected login URL to be captured, got %q", state.LoginURL)
	}
}

func TestBuildWorkerPayloadIncludesAuthAndProofContext(t *testing.T) {
	auth := &AuthState{
		Cookies:  map[string]string{"session": "abc123"},
		Headers:  map[string]string{"Authorization": "Bearer token-value-12345"},
		LoginURL: "https://example.com/login",
	}
	spec := SwarmAgentSpec{
		Type:     "Auth Discovery",
		Target:   "/admin",
		Context:  "authenticated admin workflow behind login",
		Priority: "high",
	}

	payload := buildWorkerPayload("https://example.com", spec, "", auth)
	if payload["requires_auth"] != true {
		t.Fatalf("expected requires_auth=true, got %#v", payload["requires_auth"])
	}
	if payload["proof_requirement"] == "" {
		t.Fatal("expected proof requirement to be set")
	}
	if payload["attack_graph_node"] == "" {
		t.Fatal("expected attack graph node id to be present")
	}
	if payload["auth"] == nil {
		t.Fatal("expected auth payload to be preserved")
	}
	context, _ := payload["context"].(string)
	if context == "" || !strings.Contains(context, "Preserve and reuse this auth context") {
		t.Fatalf("expected auth continuity instructions in context, got %q", context)
	}
}

func TestShouldPromoteFindingRequiresRecognizedProofModes(t *testing.T) {
	speculative := &Finding{
		Type:     "SQLi",
		URL:      "https://example.com/search",
		Severity: "high",
		Evidence: map[string]interface{}{
			"sql_error": "You have an error in your SQL syntax",
		},
	}
	if ok, _ := shouldPromoteFinding(speculative); ok {
		t.Fatal("expected SQL error without request context to stay unpromoted")
	}

	confirmed := &Finding{
		Type:     "SQLi",
		URL:      "https://example.com/search",
		Severity: "high",
		Evidence: map[string]interface{}{
			"request":  "GET /search?q=1%27 HTTP/1.1",
			"response": "500 Internal Server Error\nSQL syntax error near ...",
		},
	}
	if ok, reason := shouldPromoteFinding(confirmed); !ok {
		t.Fatalf("expected request/response proof to promote finding, got %q", reason)
	}
	if confirmed.Evidence["proof_class"] != string(proofClassRequestResponse) {
		t.Fatalf("expected proof_class to be recorded, got %#v", confirmed.Evidence["proof_class"])
	}
}

func TestAttackGraphTracksLeadHypothesisAndFinding(t *testing.T) {
	brain := &Brain{}
	updateLeadAttackGraph(brain, "https://example.com", "Admin panel discovered at /admin")
	updateHypothesisAttackGraph(brain, "https://example.com", SwarmAgentSpec{
		Type:         "Auth Discovery",
		Target:       "/admin",
		Context:      "Admin panel discovered at /admin",
		Hypothesis:   "Authenticated admin workflow may expose broken access control.",
		Proof:        "request_response",
		RequiresAuth: true,
		AuthContext:  "Login URL: https://example.com/login",
		Priority:     "high",
	})
	updateFindingAttackGraph(brain, "https://example.com", &Finding{
		Type:     "IDOR",
		URL:      "https://example.com/admin",
		Severity: "high",
		Evidence: map[string]interface{}{
			"request":  "GET /admin?id=2 HTTP/1.1",
			"response": "200 OK\nother user's record",
		},
	})

	if brain.CausalGraph == nil || len(brain.CausalGraph.Nodes) < 3 {
		t.Fatalf("expected attack graph nodes to be recorded, got %#v", brain.CausalGraph)
	}
	if len(brain.CausalGraph.Edges) == 0 {
		t.Fatal("expected attack graph edges to be recorded")
	}
}
