package agent

import (
	"strings"
	"testing"
)

// TestAllZeroDayPatterns_HaveVectors ensures every registered pattern has at least one test vector.
func TestAllZeroDayPatterns_HaveVectors(t *testing.T) {
	for _, p := range AllZeroDayPatterns {
		if len(p.TestVectors) == 0 {
			t.Errorf("pattern %q has no test vectors", p.ID)
		}
		for i, v := range p.TestVectors {
			if v.PayloadFunc == nil {
				t.Errorf("pattern %q vector[%d] has nil PayloadFunc", p.ID, i)
			}
		}
	}
}

// TestAllZeroDayPatterns_RequiredFields ensures each pattern has ID, Name, CWE, and Indicators.
func TestAllZeroDayPatterns_RequiredFields(t *testing.T) {
	for _, p := range AllZeroDayPatterns {
		if p.ID == "" {
			t.Errorf("pattern missing ID: %+v", p)
		}
		if p.Name == "" {
			t.Errorf("pattern %q missing Name", p.ID)
		}
		if p.CWE == "" {
			t.Errorf("pattern %q missing CWE", p.ID)
		}
		if len(p.Indicators) == 0 {
			t.Errorf("pattern %q has no indicators", p.ID)
		}
	}
}

// TestMatchPatterns_CRLFPattern verifies the CRLF/HTTP splitting pattern is matched
// by "redirect" and "location header" leads.
func TestMatchPatterns_CRLFPattern(t *testing.T) {
	leads := []string{"redirect", "location header"}
	matched := MatchPatterns(leads, nil)
	found := false
	for _, m := range matched {
		if m.ID == "http-request-splitting" {
			found = true
		}
	}
	if !found {
		t.Error("expected http-request-splitting to match 'redirect location header' leads")
	}
}

// TestMatchPatterns_JWTPattern verifies the JWT algorithm confusion pattern is matched.
func TestMatchPatterns_JWTPattern(t *testing.T) {
	leads := []string{"authorization: bearer", "rsa public key"}
	matched := MatchPatterns(leads, nil)
	found := false
	for _, m := range matched {
		if m.ID == "jwt-algorithm-confusion" {
			found = true
		}
	}
	if !found {
		t.Error("expected jwt-algorithm-confusion to match bearer/rsa leads")
	}
}

// TestMatchPatterns_GraphQLPattern verifies GraphQL batching pattern matches /graphql leads.
func TestMatchPatterns_GraphQLPattern(t *testing.T) {
	leads := []string{"/graphql endpoint"}
	matched := MatchPatterns(leads, nil)
	found := false
	for _, m := range matched {
		if m.ID == "graphql-batching-bruteforce" {
			found = true
		}
	}
	if !found {
		t.Error("expected graphql-batching-bruteforce to match /graphql lead")
	}
}

// TestMatchPatterns_RaceConditionPattern verifies race condition pattern matches coupon/voucher.
func TestMatchPatterns_RaceConditionPattern(t *testing.T) {
	leads := []string{"coupon redeem gift card"}
	matched := MatchPatterns(leads, nil)
	found := false
	for _, m := range matched {
		if m.ID == "race-condition-limit-bypass" {
			found = true
		}
	}
	if !found {
		t.Error("expected race-condition-limit-bypass to match coupon/redeem leads")
	}
}

// TestMatchPatterns_TechStackContributes verifies that tech stack text feeds matching.
func TestMatchPatterns_TechStackContributes(t *testing.T) {
	// graphql in the tech stack should match the graphql pattern even without explicit leads
	matched := MatchPatterns(nil, &TechStack{Frameworks: []string{"graphql"}})
	found := false
	for _, m := range matched {
		if m.ID == "graphql-batching-bruteforce" {
			found = true
		}
	}
	if !found {
		t.Error("expected graphql-batching-bruteforce to match tech stack with graphql framework")
	}
}

// TestMatchPatterns_NilTechStack verifies no panic with nil tech stack.
func TestMatchPatterns_NilTechStack(t *testing.T) {
	// Should not panic
	_ = MatchPatterns([]string{"redirect"}, nil)
}

// TestMatchPatterns_NoMatch verifies empty leads + empty stack returns empty slice.
func TestMatchPatterns_NoMatch(t *testing.T) {
	matched := MatchPatterns([]string{"nothing-relevant-at-all-xyz123"}, nil)
	if len(matched) != 0 {
		t.Errorf("expected zero matches for irrelevant leads, got %d", len(matched))
	}
}

// TestBuildZeroDayProbeURLs_CRLFPattern verifies probe URLs include CRLF injection markers.
func TestBuildZeroDayProbeURLs_CRLFPattern(t *testing.T) {
	var crlfPattern ZeroDayPattern
	for _, p := range AllZeroDayPatterns {
		if p.ID == "http-request-splitting" {
			crlfPattern = p
			break
		}
	}
	if crlfPattern.ID == "" {
		t.Skip("http-request-splitting pattern not found, skipping")
	}
	urls := BuildZeroDayProbeURLs(crlfPattern, "https://example.com/page")
	if len(urls) == 0 {
		t.Fatal("expected at least one probe URL for CRLF pattern")
	}
	hasCRLF := false
	for _, u := range urls {
		if strings.Contains(u, "%0d%0a") || strings.Contains(u, "\r\n") {
			hasCRLF = true
		}
	}
	if !hasCRLF {
		t.Errorf("expected at least one CRLF probe URL, got: %v", urls)
	}
}

// TestBuildZeroDayProbeURLs_InvalidURL verifies nil is returned for unparseable URLs.
func TestBuildZeroDayProbeURLs_InvalidURL(t *testing.T) {
	p := AllZeroDayPatterns[0]
	urls := BuildZeroDayProbeURLs(p, "://not-a-url")
	if urls != nil {
		t.Errorf("expected nil for invalid base URL, got %v", urls)
	}
}

// TestBuildZeroDayProbeURLs_StripPath verifies that probe URLs are built from scheme+host only.
func TestBuildZeroDayProbeURLs_StripPath(t *testing.T) {
	var paramPollution ZeroDayPattern
	for _, p := range AllZeroDayPatterns {
		if p.ID == "parameter-pollution-chain" {
			paramPollution = p
			break
		}
	}
	if paramPollution.ID == "" {
		t.Skip("parameter-pollution-chain not found")
	}
	urls := BuildZeroDayProbeURLs(paramPollution, "https://example.com/api/v1/users?id=5")
	for _, u := range urls {
		if strings.Contains(u, "/api/v1/users") {
			t.Errorf("probe URL should be based on scheme+host only, but got path: %s", u)
		}
	}
}
