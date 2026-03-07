package agent

import (
	"testing"

	"github.com/bb-agent/mirage/internal/models"
)

func TestOutcomeForLoopResult(t *testing.T) {
	tests := []struct {
		name        string
		result      string
		wantStatus  models.SubTaskStatus
		wantOutcome models.SubTaskOutcome
	}{
		{
			name:        "victory hierarchy confirms task",
			result:      "VICTORY HIERARCHY: confirmed impact",
			wantStatus:  models.SubTaskStatusCompleted,
			wantOutcome: models.SubTaskOutcomeConfirmed,
		},
		{
			name:        "cancellation is runtime block",
			result:      "Cancelled",
			wantStatus:  models.SubTaskStatusFailed,
			wantOutcome: models.SubTaskOutcomeBlockedByRuntime,
		},
		{
			name:        "max iterations exhausts task",
			result:      "Max iterations reached",
			wantStatus:  models.SubTaskStatusCompleted,
			wantOutcome: models.SubTaskOutcomeExhausted,
		},
		{
			name:        "generic result is completed",
			result:      "Task completed.\n\nSummary: collected evidence",
			wantStatus:  models.SubTaskStatusCompleted,
			wantOutcome: models.SubTaskOutcomeCompleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotOutcome := outcomeForLoopResult(tt.result)
			if gotStatus != tt.wantStatus || gotOutcome != tt.wantOutcome {
				t.Fatalf("outcomeForLoopResult(%q) = (%s, %s), want (%s, %s)", tt.result, gotStatus, gotOutcome, tt.wantStatus, tt.wantOutcome)
			}
		})
	}
}

func TestBuildEvidenceProofIncludesNormalizedArtifactsAndProofMetadata(t *testing.T) {
	finding := &Finding{
		Type:     "SQLi",
		URL:      "https://example.com/search",
		Severity: "high",
		Method:   "GET",
		Payload:  "1' OR '1'='1",
		Evidence: map[string]interface{}{
			"request":          "GET /search?q=1%27 HTTP/1.1",
			"response":         "500 Internal Server Error\nSQL syntax error",
			"request_headers":  map[string]any{"Cookie": "session=abc"},
			"response_headers": map[string]any{"Content-Type": "text/html"},
		},
	}

	proof := buildEvidenceProof(finding, "validated exploit path")
	if proof["proof_class"] != string(proofClassRequestResponse) {
		t.Fatalf("expected proof_class request_response, got %#v", proof["proof_class"])
	}
	if proof["proof_reason"] == "" {
		t.Fatal("expected proof_reason to be recorded")
	}
	artifacts, ok := proof["artifacts"].([]map[string]any)
	if !ok {
		t.Fatalf("expected normalized artifacts, got %#v", proof["artifacts"])
	}
	if len(artifacts) < 2 {
		t.Fatalf("expected request and response artifacts, got %#v", artifacts)
	}
	if artifacts[0]["type"] != "http_request" {
		t.Fatalf("expected first artifact to be http_request, got %#v", artifacts[0])
	}
	metadata, ok := artifacts[0]["metadata"].(map[string]any)
	if !ok || metadata["method"] != "GET" {
		t.Fatalf("expected request metadata to preserve method, got %#v", artifacts[0]["metadata"])
	}
}

func TestBuildEvidenceProofIncludesTimingAndOOBArtifacts(t *testing.T) {
	finding := &Finding{
		Type:     "SSRF",
		URL:      "https://example.com/fetch",
		Severity: "high",
		Evidence: map[string]interface{}{
			"timing_delta":     4200,
			"oob_type":         "dns",
			"oob_remote":       "interactsh.example",
			"oob_token":        "abc123",
			"callback":         "dns://abc123.interactsh.example",
			"request":          "POST /fetch HTTP/1.1",
			"response":         "202 Accepted",
			"response_time_ms": 4300,
		},
	}

	proof := buildEvidenceProof(finding, "blind interaction observed")
	artifacts, ok := proof["artifacts"].([]map[string]any)
	if !ok {
		t.Fatalf("expected normalized artifacts, got %#v", proof["artifacts"])
	}
	var sawTiming bool
	var sawOOB bool
	for _, artifact := range artifacts {
		switch artifact["type"] {
		case "timing":
			sawTiming = true
		case "oob":
			sawOOB = true
		}
	}
	if !sawTiming || !sawOOB {
		t.Fatalf("expected timing and oob artifacts, got %#v", artifacts)
	}
}
