package agent

import "testing"

func TestNormalizeBrainNoteRejectsParserArtifacts(t *testing.T) {
	if got := normalizeBrainNote("http://W3C//DTD XHTML 1.0 Transitional//EN"); got != "" {
		t.Fatalf("expected parser artifact to be discarded, got %q", got)
	}
}

func TestFilterDispatchSpecsSkipsDuplicatesAndBrowserSpecsWhenDisabled(t *testing.T) {
	dispatched := map[string]struct{}{
		dispatchFingerprint(SwarmAgentSpec{Type: "XSS", Target: "http://example.com/search"}, "http://example.com"): {},
	}

	specs := []SwarmAgentSpec{
		{Type: "XSS", Target: "http://example.com/search", Priority: "high"},
		{Type: "Visual Crawler", Target: "http://example.com", Priority: "medium"},
		{Type: "SQLi", Target: "http://example.com/login", Priority: "high"},
		{Type: "SQLi", Target: "http://example.com/login", Priority: "high"},
	}

	filtered := filterDispatchSpecs(specs, dispatched, "http://example.com", false)
	if len(filtered) != 1 {
		t.Fatalf("expected only one remaining spec, got %d: %+v", len(filtered), filtered)
	}
	if filtered[0].Type != "SQLi" {
		t.Fatalf("expected SQLi to remain after filtering, got %+v", filtered[0])
	}
}

func TestDispatchFingerprintIncludesContext(t *testing.T) {
	first := dispatchFingerprint(SwarmAgentSpec{
		Type:    "SQLi",
		Target:  "http://example.com/login",
		Context: "unauthenticated login form",
	}, "http://example.com")

	second := dispatchFingerprint(SwarmAgentSpec{
		Type:    "SQLi",
		Target:  "http://example.com/login",
		Context: "authenticated admin session after security level change",
	}, "http://example.com")

	if first == second {
		t.Fatal("expected dispatch fingerprint to differ when context changes materially")
	}
}

func TestBuildFallbackAgentSpecsUsesBrainSignals(t *testing.T) {
	brain := &Brain{
		Leads: []string{
			"Login page discovered at /login.php with default credential hints",
			"Potential SQL injection in /vulnerabilities/sqli/",
		},
	}

	specs := buildFallbackAgentSpecs("http://example.com", brain)
	if len(specs) == 0 {
		t.Fatal("expected fallback planner to emit at least one specialist")
	}

	foundAuth := false
	foundSQLi := false
	for _, spec := range specs {
		switch normalizeSpecialistName(spec.Type) {
		case "authdiscovery":
			foundAuth = true
		case "sqli":
			foundSQLi = true
		}
	}

	if !foundAuth || !foundSQLi {
		t.Fatalf("expected auth and sqli fallback specs, got %+v", specs)
	}
}
