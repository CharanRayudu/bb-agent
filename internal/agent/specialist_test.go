package agent

import "testing"

func TestShouldRouteFindingToLeadForHypothesisOnlyFinding(t *testing.T) {
	f := &Finding{
		Type:       "SQLi",
		URL:        "http://example.com/search",
		Confidence: 0,
		Evidence: map[string]interface{}{
			"sqli_type": "error_based",
			"dbms_hint": "unknown",
		},
	}

	if !shouldRouteFindingToLead(f) {
		t.Fatal("expected metadata-only finding to be routed as a lead")
	}
}

func TestShouldRouteFindingToLeadFalseWhenConcreteEvidenceExists(t *testing.T) {
	f := &Finding{
		Type: "SQLi",
		URL:  "http://example.com/search",
		Evidence: map[string]interface{}{
			"request":  "GET /search?id=1'",
			"response": "SQL syntax error near ...",
		},
	}

	if shouldRouteFindingToLead(f) {
		t.Fatal("expected finding with concrete evidence to remain a finding")
	}
}
