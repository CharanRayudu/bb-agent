package schema

import (
	"testing"
)

// ---------------------------------------------------------------------------
// ExtractJSON Tests
// ---------------------------------------------------------------------------

func TestExtractJSON_RawArray(t *testing.T) {
	input := `[{"type":"XSS","priority":"high"},{"type":"SQLi","priority":"medium"}]`
	result := ExtractJSON(input)
	if result != input {
		t.Errorf("Expected raw JSON passthrough, got: %s", result)
	}
}

func TestExtractJSON_RawObject(t *testing.T) {
	input := `{"specs":[{"type":"XSS"}]}`
	result := ExtractJSON(input)
	if result != input {
		t.Errorf("Expected raw JSON object passthrough, got: %s", result)
	}
}

func TestExtractJSON_CodeFence(t *testing.T) {
	input := "Here is the output:\n```json\n[{\"type\":\"XSS\"}]\n```\nHope this helps!"
	result := ExtractJSON(input)
	expected := `[{"type":"XSS"}]`
	if result != expected {
		t.Errorf("Expected %s, got: %s", expected, result)
	}
}

func TestExtractJSON_CodeFenceNoLanguage(t *testing.T) {
	input := "```\n{\"specs\":[{\"type\":\"SQLi\"}]}\n```"
	result := ExtractJSON(input)
	expected := `{"specs":[{"type":"SQLi"}]}`
	if result != expected {
		t.Errorf("Expected %s, got: %s", expected, result)
	}
}

func TestExtractJSON_EscapedString(t *testing.T) {
	input := `"[{\"type\":\"SSRF\",\"priority\":\"critical\"}]"`
	result := ExtractJSON(input)
	expected := `[{"type":"SSRF","priority":"critical"}]`
	if result != expected {
		t.Errorf("Expected %s, got: %s", expected, result)
	}
}

func TestExtractJSON_EmbeddedInText(t *testing.T) {
	input := `Based on my analysis, here are the specialists needed:
[{"type":"XSS","target":"https://example.com/search","priority":"high"}]
I recommend starting with XSS testing.`
	result := ExtractJSON(input)
	if result == "" {
		t.Error("Expected to extract embedded JSON, got empty string")
	}
}

func TestExtractJSON_Empty(t *testing.T) {
	result := ExtractJSON("")
	if result != "" {
		t.Errorf("Expected empty for empty input, got: %s", result)
	}
}

func TestExtractJSON_NoJSON(t *testing.T) {
	input := "I couldn't find any vulnerabilities in this application."
	result := ExtractJSON(input)
	if result != "" {
		t.Errorf("Expected empty for non-JSON input, got: %s", result)
	}
}

// ---------------------------------------------------------------------------
// Parse Tests -- PlannerOutput
// ---------------------------------------------------------------------------

func TestParse_PlannerOutput_Valid(t *testing.T) {
	input := `{"specs":[{"type":"XSS","priority":"high"},{"type":"SQLi","target":"https://example.com/login"}]}`
	result, err := Parse[PlannerOutput](input)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(result.Specs) != 2 {
		t.Errorf("Expected 2 specs, got %d", len(result.Specs))
	}
	if result.Specs[0].Type != "XSS" {
		t.Errorf("Expected first spec type XSS, got %s", result.Specs[0].Type)
	}
	// Verify default priority was applied
	if result.Specs[1].Priority != "medium" {
		t.Errorf("Expected default priority 'medium', got %s", result.Specs[1].Priority)
	}
}

func TestParse_PlannerOutput_EmptySpecs(t *testing.T) {
	input := `{"specs":[]}`
	_, err := Parse[PlannerOutput](input)
	if err == nil {
		t.Error("Expected validation error for empty specs")
	}
}

func TestParse_PlannerOutput_MissingType(t *testing.T) {
	input := `{"specs":[{"priority":"high"}]}`
	_, err := Parse[PlannerOutput](input)
	if err == nil {
		t.Error("Expected validation error for missing type")
	}
}

func TestParse_PlannerOutput_InCodeFence(t *testing.T) {
	input := "```json\n{\"specs\":[{\"type\":\"SSRF\",\"priority\":\"critical\"}]}\n```"
	result, err := Parse[PlannerOutput](input)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(result.Specs) != 1 {
		t.Errorf("Expected 1 spec, got %d", len(result.Specs))
	}
}

func TestParsePlannerOutput_RepairsBareArray(t *testing.T) {
	input := `[{"type":"XSS","priority":"high"},{"type":"SQLi","target":"https://example.com/login"}]`
	result, err := ParsePlannerOutput(input)
	if err != nil {
		t.Fatalf("expected repairable planner array to parse, got: %v", err)
	}
	if len(result.Specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(result.Specs))
	}
	if result.Specs[1].Priority != "medium" {
		t.Fatalf("expected default priority to be applied, got %s", result.Specs[1].Priority)
	}
}

func TestParsePlannerOutput_RepairsAgentsWrapper(t *testing.T) {
	input := `{"agents":[{"type":"SSRF","priority":"critical"}]}`
	result, err := ParsePlannerOutput(input)
	if err != nil {
		t.Fatalf("expected agents wrapper to parse, got: %v", err)
	}
	if len(result.Specs) != 1 || result.Specs[0].Type != "SSRF" {
		t.Fatalf("unexpected repaired planner output: %+v", result.Specs)
	}
}

func TestParsePlannerOutput_RepairsPlainTextPlannerResponse(t *testing.T) {
	input := "Dispatch XSS (high) for /search and SQLi (medium) for https://example.com/login.php. Keep SSRF low priority."
	result, err := ParsePlannerOutput(input)
	if err != nil {
		t.Fatalf("expected plain text planner output to be repaired, got: %v", err)
	}
	if len(result.Specs) != 3 {
		t.Fatalf("expected 3 repaired specs, got %d", len(result.Specs))
	}
}

func TestParse_PlannerOutput_NoJSON(t *testing.T) {
	input := "I think we should test for XSS and SQLi vulnerabilities."
	_, err := Parse[PlannerOutput](input)
	if err == nil {
		t.Error("Expected error for non-JSON input")
	}
}

// ---------------------------------------------------------------------------
// Parse Tests -- FindingsOutput
// ---------------------------------------------------------------------------

func TestParse_FindingsOutput_Valid(t *testing.T) {
	input := `{"findings":[{"type":"XSS","url":"https://example.com/search","severity":"high","parameter":"q"}]}`
	result, err := Parse[FindingsOutput](input)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(result.Findings))
	}
}

func TestParse_FindingsOutput_InvalidURL(t *testing.T) {
	input := `{"findings":[{"type":"XSS","url":"not-a-url","severity":"high"}]}`
	_, err := Parse[FindingsOutput](input)
	if err == nil {
		t.Error("Expected validation error for invalid URL")
	}
}

func TestParse_FindingsOutput_MissingSeverity(t *testing.T) {
	input := `{"findings":[{"type":"XSS","url":"https://example.com/search"}]}`
	_, err := Parse[FindingsOutput](input)
	if err == nil {
		t.Error("Expected validation error for missing severity")
	}
}

// ---------------------------------------------------------------------------
// CorrectionPrompt Tests
// ---------------------------------------------------------------------------

func TestCorrectionPrompt_ContainsError(t *testing.T) {
	err := &validationTestError{msg: "missing field 'type'"}
	prompt := CorrectionPrompt(err, "bad response")
	if prompt == "" {
		t.Error("Expected non-empty correction prompt")
	}
	if !containsSubstring(prompt, "missing field 'type'") {
		t.Error("Correction prompt should contain the original error message")
	}
}

// helpers
type validationTestError struct{ msg string }

func (e *validationTestError) Error() string { return e.msg }

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && findSubstring(s, sub)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
