package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/google/uuid"
)

func TestVerifyFindingDeterministicRequiresProof(t *testing.T) {
	hyp := VerifyFindingDeterministic(&Finding{Type: "XSS", URL: "https://example.com/", Severity: "medium"})
	if hyp.Status != VerificationHypothesis && hyp.Status != VerificationNeedsProof {
		t.Fatalf("status=%s", hyp.Status)
	}

	unproven := VerifyFindingDeterministic(&Finding{
		Type: "SQLi", URL: "https://example.com/q", Severity: "high",
		Evidence: map[string]interface{}{"sql_error": "syntax error"},
	})
	if unproven.Status != VerificationNeedsProof {
		t.Fatalf("status=%s reason=%s", unproven.Status, unproven.Reason)
	}

	ok := VerifyFindingDeterministic(&Finding{
		Type: "SQLi", URL: "https://example.com/q", Severity: "high", Confidence: 0.9,
		Evidence: map[string]interface{}{
			"request":  "GET /q?x=1' HTTP/1.1",
			"response": "500 SQL syntax error",
		},
	})
	if ok.Status != VerificationConfirmed || ok.ProofClass != string(proofClassRequestResponse) {
		t.Fatalf("got %+v", ok)
	}
}

func TestPartitionFindingsSeparatesUnverified(t *testing.T) {
	findings := []*Finding{
		{Type: "XSS", URL: "https://example.com/a", Severity: "low"},
		{
			Type: "SQLi", URL: "https://example.com/b", Severity: "high", Confidence: 0.95,
			Evidence: map[string]interface{}{"request": "GET /b", "response": "error"},
		},
	}
	part := PartitionFindingsForReport(findings, nil)
	if len(part.Confirmed) != 1 || len(part.NeedsProof)+len(part.Hypothesis) != 1 {
		t.Fatalf("counts=%v", part.Counts())
	}
	if len(part.ConfirmedFindings()) != 1 {
		t.Fatal("confirmed findings mismatch")
	}
}

func TestReflectorValidateFindingFailsClosedOnLLMError(t *testing.T) {
	r := NewReflector(failingLLM{})
	ok, reason := r.ValidateFinding(context.Background(), "directive", nil, "finding")
	if ok {
		t.Fatal("expected fail-closed rejection")
	}
	if !strings.Contains(strings.ToLower(reason), "deterministic") {
		t.Fatalf("reason=%q", reason)
	}
}

func TestReportIncludesVerificationAndEnvironment(t *testing.T) {
	rg := NewReportGenerator()
	confirmed := &Finding{
		Type: "SQLi", URL: "https://lab/q", Severity: "high", Confidence: 1,
		Evidence: map[string]interface{}{"request": "GET", "response": "err"},
	}
	part := PartitionFindingsForReport([]*Finding{confirmed, {Type: "XSS", URL: "https://lab/x", Severity: "low"}}, nil)
	out := rg.GenerateReportWithEvidence(
		"https://lab", uuid.MustParse("00000000-0000-0000-0000-0000000000bb"), time.Second,
		"recon", part.ConfirmedFindings(), nil, nil, "", "", nil, nil,
		ExecutionHealth{Verdict: ObserverContinue},
		part,
		EnvironmentSnapshot{CapturedAt: time.Unix(1, 0).UTC(), GoVersion: "go1.test", SandboxImage: "mirage-tools:vtest", LLMModel: "stub"},
	)
	for _, want := range []string{"## Verification Status", "confirmed", "needs_proof", "## Environment Snapshot", "mirage-tools:vtest"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "### Finding 2:") {
		t.Fatal("unverified finding should not appear in detailed confirmed findings")
	}
}

type failingLLM struct{}

func (failingLLM) Name() string { return "failing" }
func (failingLLM) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, errors.New("llm unavailable")
}
