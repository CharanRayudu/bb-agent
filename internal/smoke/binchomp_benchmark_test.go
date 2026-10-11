package smoke

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bb-agent/mirage/internal/agent"
)

// TestBinChompValidationBenchmark measures deterministic verification vs prior
// fail-open reflector behavior using synthetic findings only (no live targets).
func TestBinChompValidationBenchmark(t *testing.T) {
	metrics := map[string]any{}

	// Baseline behavior (documented): Reflector.ValidateFinding used to return
	// true when the LLM failed ("automatically accepting"). Updated: fail closed.
	r := agent.NewReflector(permanentModelStub{})
	ok, _ := r.ValidateFinding(context.Background(), "directive", nil, "claimed finding")
	metrics["reflector_fail_closed"] = !ok
	if ok {
		t.Fatal("updated reflector must not auto-accept when LLM fails")
	}

	findings := []*agent.Finding{
		{Type: "XSS", URL: "http://203.0.113.10/x", Severity: "low"},
		{
			Type: "SQLi", URL: "http://203.0.113.10/q", Severity: "high", Confidence: 0.95,
			Evidence: map[string]interface{}{
				"request":  "GET /q?id=1'",
				"response": "SQL syntax error",
			},
		},
	}
	part := agent.PartitionFindingsForReport(findings, nil)
	counts := part.Counts()
	metrics["validated_confirmed"] = counts["confirmed"]
	metrics["unverified_needs_proof_or_hypothesis"] = counts["needs_proof"] + counts["hypothesis"]
	metrics["report_confirmed_only"] = len(part.ConfirmedFindings()) == counts["confirmed"]
	metrics["env_snapshot_has_go"] = agent.CaptureEnvironmentSnapshot(nil).GoVersion != ""

	if counts["confirmed"] != 1 || counts["needs_proof"]+counts["hypothesis"] != 1 {
		t.Fatalf("unexpected partition counts: %v", counts)
	}
	if !metrics["reflector_fail_closed"].(bool) || !metrics["report_confirmed_only"].(bool) {
		t.Fatalf("benchmark gates failed: %v", metrics)
	}
	b, _ := json.Marshal(metrics)
	t.Logf("BINCHOMP_VALIDATION_METRICS %s", string(b))
}
