package schema

import "testing"

func TestParsePlannerOutputPreservesAuthAndProofFields(t *testing.T) {
	input := `{"specs":[{"type":"SSRF","target":"https://example.com/fetch","context":"Authenticated fetch endpoint","hypothesis":"Authenticated SSRF may reach internal metadata","proof":"oob","requires_auth":true,"auth_context":"Bearer token + session cookie","priority":"high"}]}`
	result, err := ParsePlannerOutput(input)
	if err != nil {
		t.Fatalf("expected planner output to parse, got %v", err)
	}
	if len(result.Specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(result.Specs))
	}
	spec := result.Specs[0]
	if !spec.RequiresAuth {
		t.Fatal("expected requires_auth to round-trip")
	}
	if spec.Proof != "oob" {
		t.Fatalf("expected proof field to round-trip, got %q", spec.Proof)
	}
	if spec.AuthContext == "" || spec.Hypothesis == "" {
		t.Fatalf("expected auth_context and hypothesis to round-trip, got %+v", spec)
	}
}
