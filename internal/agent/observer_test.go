package agent

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestObserverDetectsEmptyAssessment(t *testing.T) {
	obs := NewExecutionObserver()
	obs.NoteTool("think", false)
	obs.NoteTool("complete_task", false)
	if err := obs.IncompleteAssessment(0, 0, 0); err == nil {
		t.Fatal("expected incomplete assessment when no scanners ran")
	}
	obs.NoteTool("run_security_tool", false)
	if err := obs.IncompleteAssessment(0, 0, 0); err != nil {
		t.Fatalf("security tool should allow completion: %v", err)
	}
}

func TestObserverRequestsReplanAfterRepeatedFailures(t *testing.T) {
	obs := NewExecutionObserver()
	for i := 0; i < 3; i++ {
		obs.NoteTool("nmap", true)
	}
	ok, reason := obs.ConsumeReplanRequest()
	if !ok || reason == "" {
		t.Fatalf("replan=%v reason=%q", ok, reason)
	}
	health := obs.Health()
	if health.SecurityToolRuns != 3 || health.ToolFailures != 3 {
		t.Fatalf("health=%+v", health)
	}
}

func TestReportIncludesEvidenceTrailAndHealth(t *testing.T) {
	rg := NewReportGenerator()
	out := rg.GenerateReportWithEvidence(
		"http://lab",
		uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		0,
		"recon",
		nil,
		nil,
		nil,
		"Evidence files:\n- scan.txt\n",
		"",
		[]ReportEvidenceRef{{Kind: "workspace", Name: "scan.txt", Path: "scan.txt", Tool: "nmap", Status: "ok"}},
		[]ReportEvidenceRef{{Kind: "evidence_pack", Name: "xss", Path: "11111111-1111-1111-1111-111111111111", Tool: "XSS", Status: "confirmed"}},
		ExecutionHealth{SecurityToolRuns: 1, ToolCalls: 2, Verdict: ObserverContinue},
	)
	for _, want := range []string{"## Evidence Trail", "scan.txt", "evidence_pack", "## Execution Health", "Security tool runs: 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q\n%s", want, out)
		}
	}
}
