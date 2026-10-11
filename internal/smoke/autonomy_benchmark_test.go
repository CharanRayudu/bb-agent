package smoke

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/agent"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/server"
	"github.com/google/uuid"
	"net/http/httptest"
)

// TestAutonomyBenchmarkStubbedScenarios measures observer + evidence report behavior
// with deterministic stubs (no live LLM, no unauthorized targets).
// Baseline: pre-observer Mirage would mark think-only scans completed and emit
// "No confirmed vulnerabilities" reports (observed on live lab flow 7e784808).
// Updated: IncompleteAssessment refuses green completion; reports include evidence trail.
func TestAutonomyBenchmarkStubbedScenarios(t *testing.T) {
	metrics := map[string]any{}

	// Metric A: empty assessment refused
	obs := agent.NewExecutionObserver()
	obs.NoteTool("think", false)
	obs.NoteTool("complete_task", false)
	err := obs.IncompleteAssessment(0, 0, 0)
	metrics["empty_assessment_refused"] = err != nil
	if err == nil {
		t.Fatal("updated build must refuse empty assessment")
	}

	// Metric B: security tool evidence allows completion
	obs2 := agent.NewExecutionObserver()
	obs2.NoteTool("run_security_tool", false)
	if err := obs2.IncompleteAssessment(0, 0, 0); err != nil {
		t.Fatalf("security tool should allow completion: %v", err)
	}
	metrics["security_tool_allows_completion"] = true

	// Metric C: replan after repeated failures
	obs3 := agent.NewExecutionObserver()
	for i := 0; i < 3; i++ {
		obs3.NoteTool("nmap", true)
	}
	need, reason := obs3.ConsumeReplanRequest()
	metrics["replan_after_3_failures"] = need
	metrics["replan_reason_nonempty"] = reason != ""
	if !need {
		t.Fatal("expected replan")
	}

	// Metric D: evidence-linked report sections
	rg := agent.NewReportGenerator()
	report := rg.GenerateReportWithEvidence(
		"http://203.0.113.10/",
		uuid.MustParse("00000000-0000-0000-0000-0000000000aa"),
		2*time.Second,
		"recon",
		nil, nil, nil,
		"Evidence files:\n- nmap.txt\n",
		"",
		[]agent.ReportEvidenceRef{{Kind: "workspace", Name: "nmap.txt", Path: "nmap.txt", Tool: "nmap", Status: "ok"}},
		[]agent.ReportEvidenceRef{{Kind: "evidence_pack", Name: "xss", Path: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Tool: "XSS", Status: "confirmed"}},
		agent.ExecutionHealth{SecurityToolRuns: 1, ToolCalls: 3, Verdict: agent.ObserverContinue},
		agent.VerificationPartition{},
		agent.EnvironmentSnapshot{GoVersion: "go1.test", CapturedAt: time.Unix(0, 0).UTC()},
	)
	metrics["report_has_evidence_trail"] = strings.Contains(report, "## Evidence Trail")
	metrics["report_has_execution_health"] = strings.Contains(report, "## Execution Health")
	metrics["report_lists_workspace_artifact"] = strings.Contains(report, "nmap.txt")
	metrics["report_lists_evidence_pack"] = strings.Contains(report, "evidence_pack")

	// Metric E: end-to-end stub flow fails instead of completing (updated behavior)
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)
	cfg := &config.Config{OpenAIModel: "stub", ExecutionV2: false}
	app := server.New(cfg, db)
	app.UseLLMProvider(thinkOnlyStub{})
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)
	start := time.Now()
	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name": "bench-empty", "description": "benchmark", "target": "http://203.0.113.10/",
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatal(err)
	}
	status := waitForFlowStatus(t, api.URL, flow.ID, models.FlowStatusFailed, 2*time.Minute)
	elapsed := time.Since(start)
	metrics["e2e_think_only_status"] = string(status)
	metrics["e2e_think_only_failed"] = status == models.FlowStatusFailed
	metrics["e2e_duration_ms"] = elapsed.Milliseconds()
	_, code := getBodyStatus(t, api.URL+"/api/flows/"+flow.ID.String()+"/report")
	metrics["e2e_report_http_status"] = code
	metrics["e2e_successful_report_blocked"] = code == 404

	if status != models.FlowStatusFailed || code != 404 {
		t.Fatalf("updated autonomy metrics failed: status=%s report=%d metrics=%v", status, code, metrics)
	}

	t.Logf("AUTONOMY_BENCHMARK_METRICS %s", mustJSON(metrics))
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
