package agent

import (
	"context"
	"testing"
)

// TestHypothesisEngine_NilProvider_RuleBasedFallback verifies that a nil provider
// triggers ruleBasedHypotheses and returns a non-empty slice.
func TestHypothesisEngine_NilProvider_RuleBasedFallback(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, err := he.Generate(context.Background(), "https://example.com", []string{"sql", "id=1"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hyps) == 0 {
		t.Fatal("expected at least one hypothesis from rule-based fallback")
	}
}

// TestHypothesisEngine_RuleBasedFallback_SQLi verifies the SQLi hypothesis is generated
// when SQL-related signals are present.
func TestHypothesisEngine_RuleBasedFallback_SQLi(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com", []string{"search", "query param", "id="}, &TechStack{DB: "mysql"}, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "SQLi" {
			found = true
			if h.Priority < 8 {
				t.Errorf("SQLi priority %d < 8", h.Priority)
			}
			if h.Confidence <= 0 {
				t.Error("SQLi confidence should be > 0")
			}
		}
	}
	if !found {
		t.Error("expected SQLi hypothesis for SQL signals, got none")
	}
}

// TestHypothesisEngine_RuleBasedFallback_SSRF verifies the SSRF hypothesis is generated
// when URL/webhook signals are present.
func TestHypothesisEngine_RuleBasedFallback_SSRF(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com", []string{"webhook callback url"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "SSRF" {
			found = true
			if h.Priority < 9 {
				t.Errorf("SSRF priority %d < 9", h.Priority)
			}
		}
	}
	if !found {
		t.Error("expected SSRF hypothesis for URL/webhook signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_IDOR verifies IDOR hypothesis for user/account signals.
func TestHypothesisEngine_RuleBasedFallback_IDOR(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com/api/users", []string{"user profile account resource"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "IDOR" {
			found = true
		}
	}
	if !found {
		t.Error("expected IDOR hypothesis for user/account signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_AuthBypass verifies AuthBypass is always generated.
func TestHypothesisEngine_RuleBasedFallback_AuthBypass(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com", []string{}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "AuthBypass" {
			found = true
		}
	}
	if !found {
		t.Error("expected AuthBypass hypothesis — it should always be generated")
	}
}

// TestHypothesisEngine_RuleBasedFallback_JWT verifies JWT hypothesis when token signals present.
func TestHypothesisEngine_RuleBasedFallback_JWT(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com", []string{"jwt bearer authorization token"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "JWT" {
			found = true
			if !h.ZeroDayRisk {
				t.Error("JWT hypothesis should set ZeroDayRisk=true (algorithm confusion is novel)")
			}
		}
	}
	if !found {
		t.Error("expected JWT hypothesis for bearer/token signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_BusinessLogic verifies business logic hypothesis
// for payment/coupon signals.
func TestHypothesisEngine_RuleBasedFallback_BusinessLogic(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://shop.com/checkout", []string{"payment coupon discount cart"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "BusinessLogic" {
			found = true
		}
	}
	if !found {
		t.Error("expected BusinessLogic hypothesis for payment/coupon signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_GraphQL verifies GraphQL hypothesis.
func TestHypothesisEngine_RuleBasedFallback_GraphQL(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://api.example.com/graphql", []string{"graphql endpoint"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "GraphQL" {
			found = true
		}
	}
	if !found {
		t.Error("expected GraphQL hypothesis for graphql signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_XSS verifies XSS hypothesis for input/form signals.
func TestHypothesisEngine_RuleBasedFallback_XSS(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com/search", []string{"search input form query"}, nil, nil)
	found := false
	for _, h := range hyps {
		if h.VulnClass == "XSS" {
			found = true
		}
	}
	if !found {
		t.Error("expected XSS hypothesis for search/input/form signals")
	}
}

// TestHypothesisEngine_RuleBasedFallback_SortedByPriority verifies output is sorted descending.
func TestHypothesisEngine_RuleBasedFallback_SortedByPriority(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyps, _ := he.Generate(context.Background(), "https://example.com", []string{"sql url jwt search graphql payment"}, &TechStack{DB: "postgres"}, nil)
	for i := 1; i < len(hyps); i++ {
		if hyps[i].Priority > hyps[i-1].Priority {
			t.Errorf("hypotheses not sorted: position %d priority %d > position %d priority %d",
				i, hyps[i].Priority, i-1, hyps[i-1].Priority)
		}
	}
}

// TestHypothesisEngine_RefineSingle_Confirm verifies confidence increases on success.
func TestHypothesisEngine_RefineSingle_Confirm(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	original := AttackHypothesis{Confidence: 0.5, Evidence: []string{}}
	refined := he.RefineSingle(context.Background(), original, "payload reflected", true)
	if refined.Confidence <= original.Confidence {
		t.Errorf("confirmed hypothesis confidence %.2f did not increase from %.2f",
			refined.Confidence, original.Confidence)
	}
	if len(refined.Evidence) == 0 {
		t.Error("expected evidence entry to be added on confirmation")
	}
}

// TestHypothesisEngine_RefineSingle_Deny verifies confidence decreases on failure.
func TestHypothesisEngine_RefineSingle_Deny(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	original := AttackHypothesis{Confidence: 0.5, Evidence: []string{}}
	refined := he.RefineSingle(context.Background(), original, "payload blocked", false)
	if refined.Confidence >= original.Confidence {
		t.Errorf("denied hypothesis confidence %.2f did not decrease from %.2f",
			refined.Confidence, original.Confidence)
	}
}

// TestHypothesisEngine_RefineSingle_CapAt1(verifies confidence doesn't exceed 1.0.
func TestHypothesisEngine_RefineSingle_CapAt1(t *testing.T) {
	he := NewHypothesisEngine(nil, "")
	hyp := AttackHypothesis{Confidence: 0.99, Evidence: []string{}}
	for i := 0; i < 5; i++ {
		hyp = he.RefineSingle(context.Background(), hyp, "confirmed", true)
	}
	if hyp.Confidence > 1.0 {
		t.Errorf("confidence %.2f exceeds 1.0", hyp.Confidence)
	}
}
