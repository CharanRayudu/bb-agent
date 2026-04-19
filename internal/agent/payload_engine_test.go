package agent

import (
	"strings"
	"testing"
)

// TestMutatePayload_Encode verifies that encode strategy produces URL-encoded,
// HTML entity, and Unicode-encoded variants.
func TestMutatePayload_Encode(t *testing.T) {
	pe := NewPayloadEngine(nil)
	mutations := pe.MutatePayload(`<script>alert(1)</script>`, MutationEncode)
	if len(mutations) < 3 {
		t.Errorf("encode strategy should produce at least 3 variants, got %d", len(mutations))
	}
	hasURLenc := false
	hasHTMLent := false
	for _, m := range mutations {
		if strings.Contains(m, "%") {
			hasURLenc = true
		}
		if strings.Contains(m, "&#") {
			hasHTMLent = true
		}
	}
	if !hasURLenc {
		t.Error("encode strategy should produce a URL-encoded variant")
	}
	if !hasHTMLent {
		t.Error("encode strategy should produce an HTML entity-encoded variant")
	}
}

// TestMutatePayload_Case verifies case strategy produces upper-case and alternate-case variants.
func TestMutatePayload_Case(t *testing.T) {
	pe := NewPayloadEngine(nil)
	mutations := pe.MutatePayload("select", MutationCase)
	if len(mutations) < 2 {
		t.Fatalf("case strategy should produce at least 2 variants, got %d", len(mutations))
	}
	hasUpper := false
	for _, m := range mutations {
		if m == strings.ToUpper("select") {
			hasUpper = true
		}
	}
	if !hasUpper {
		t.Error("case strategy should produce a fully upper-cased variant")
	}
}

// TestMutatePayload_Obfuscate verifies null-byte and comment-insertion variants.
func TestMutatePayload_Obfuscate(t *testing.T) {
	pe := NewPayloadEngine(nil)
	mutations := pe.MutatePayload(`SELECT UNION`, MutationObfuscate)
	if len(mutations) < 2 {
		t.Fatalf("obfuscate strategy should produce at least 2 variants, got %d", len(mutations))
	}
	hasNull := false
	hasComment := false
	for _, m := range mutations {
		if strings.Contains(m, "%00") {
			hasNull = true
		}
		if strings.Contains(m, "/**/") {
			hasComment = true
		}
	}
	if !hasNull {
		t.Error("obfuscate strategy should produce a null-byte variant")
	}
	if !hasComment {
		t.Error("obfuscate strategy should produce a comment-insertion variant")
	}
}

// TestMutatePayload_Polyglot verifies JS/HTML/SQL polyglot wrapping.
func TestMutatePayload_Polyglot(t *testing.T) {
	pe := NewPayloadEngine(nil)
	mutations := pe.MutatePayload("alert(1)", MutationPolyglot)
	if len(mutations) < 3 {
		t.Fatalf("polyglot strategy should produce at least 3 variants, got %d", len(mutations))
	}
	hasJS := false
	hasHTML := false
	hasSQL := false
	for _, m := range mutations {
		if strings.Contains(m, "alert") && strings.Contains(m, "-alert(1)-") {
			hasJS = true
		}
		if strings.Contains(m, "onerror") {
			hasHTML = true
		}
		if strings.Contains(m, "OR 1=1") {
			hasSQL = true
		}
	}
	if !hasJS {
		t.Error("polyglot strategy should produce a JS context wrapper")
	}
	if !hasHTML {
		t.Error("polyglot strategy should produce an HTML onerror wrapper")
	}
	if !hasSQL {
		t.Error("polyglot strategy should produce a SQL OR-injection wrapper")
	}
}

// TestMutatePayload_DefaultPassthrough verifies unknown strategy returns original payload.
func TestMutatePayload_DefaultPassthrough(t *testing.T) {
	pe := NewPayloadEngine(nil)
	mutations := pe.MutatePayload("test-payload", "unknown_strategy")
	if len(mutations) == 0 {
		t.Error("unknown strategy should still return at least the original payload")
	}
	found := false
	for _, m := range mutations {
		if m == "test-payload" {
			found = true
		}
	}
	if !found {
		t.Error("unknown strategy should return the original payload unchanged")
	}
}

// TestPrioritizePayloads_PHPStackBubbles verifies PHP-specific payloads move to front.
func TestPrioritizePayloads_PHPStackBubbles(t *testing.T) {
	payloads := []string{
		"<script>alert(1)</script>",
		"<?php system('id'); ?>",
		"eval($_GET['cmd'])",
		"<img src=x onerror=alert(1)>",
	}
	result := PrioritizePayloads(payloads, TechStack{Lang: "PHP"}, WAFResult{Vendor: WAFNone})
	// PHP payloads should be in the first positions
	phpFound := false
	for i, p := range result[:2] {
		if strings.Contains(strings.ToLower(p), "<?php") || strings.Contains(strings.ToLower(p), "eval(") {
			phpFound = true
			_ = i
		}
	}
	if !phpFound {
		t.Errorf("PHP-specific payloads should be prioritized first, got: %v", result)
	}
}

// TestPrioritizePayloads_WAFBypassPrepended verifies WAF bypass variants are prepended.
func TestPrioritizePayloads_WAFBypassPrepended(t *testing.T) {
	payloads := []string{`' OR 1=1-- -`, `" OR 1=1-- -`}
	result := PrioritizePayloads(payloads, TechStack{}, WAFResult{Vendor: WAFCloudflare, Confidence: 0.9})
	// Result should be longer than input (bypass variants prepended)
	if len(result) <= len(payloads) {
		t.Errorf("WAF bypass variants should be prepended; got %d payloads, input had %d", len(result), len(payloads))
	}
}

// TestPrioritizePayloads_EmptyInput returns empty for empty input.
func TestPrioritizePayloads_EmptyInput(t *testing.T) {
	result := PrioritizePayloads(nil, TechStack{}, WAFResult{Vendor: WAFNone})
	if len(result) != 0 {
		t.Errorf("empty input should return empty, got %v", result)
	}
}

// TestPrioritizePayloads_NoWAFNoReorder verifies no reordering when WAF is none and
// no stack-specific keywords match — order should be preserved.
func TestPrioritizePayloads_NoWAFNoReorder(t *testing.T) {
	payloads := []string{"aaa", "bbb", "ccc"}
	result := PrioritizePayloads(payloads, TechStack{}, WAFResult{Vendor: WAFNone})
	if len(result) != len(payloads) {
		t.Fatalf("expected %d payloads, got %d", len(payloads), len(result))
	}
	for i := range payloads {
		if result[i] != payloads[i] {
			t.Errorf("order changed at position %d: expected %q got %q", i, payloads[i], result[i])
		}
	}
}

// TestRecordAndGetAttemptHistory verifies round-trip record/retrieve.
func TestRecordAndGetAttemptHistory(t *testing.T) {
	pe := NewPayloadEngine(nil)
	a1 := PayloadAttempt{Payload: `' OR 1=1-- -`, Blocked: false, Reflected: true}
	a2 := PayloadAttempt{Payload: `"><script>`, Blocked: true}
	pe.RecordAttempt("https://example.com", "id", a1)
	pe.RecordAttempt("https://example.com", "id", a2)

	hist := pe.GetAttemptHistory("https://example.com", "id")
	if len(hist) != 2 {
		t.Fatalf("expected 2 attempt history entries, got %d", len(hist))
	}
	if hist[0].Payload != a1.Payload || hist[1].Payload != a2.Payload {
		t.Error("attempt history order or content mismatch")
	}
}

// TestRecordAttempt_IsolatedByKey verifies different target+param combos don't share history.
func TestRecordAttempt_IsolatedByKey(t *testing.T) {
	pe := NewPayloadEngine(nil)
	pe.RecordAttempt("https://example.com", "id", PayloadAttempt{Payload: "a"})
	pe.RecordAttempt("https://example.com", "name", PayloadAttempt{Payload: "b"})
	pe.RecordAttempt("https://other.com", "id", PayloadAttempt{Payload: "c"})

	if len(pe.GetAttemptHistory("https://example.com", "id")) != 1 {
		t.Error("expected exactly 1 entry for example.com/id")
	}
	if len(pe.GetAttemptHistory("https://example.com", "name")) != 1 {
		t.Error("expected exactly 1 entry for example.com/name")
	}
	if len(pe.GetAttemptHistory("https://other.com", "id")) != 1 {
		t.Error("expected exactly 1 entry for other.com/id")
	}
}
