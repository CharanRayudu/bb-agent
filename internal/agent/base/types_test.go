package base

import "testing"

func TestValidateFindingRejectsSuspiciousURLArtifacts(t *testing.T) {
	err := ValidateFinding(&Finding{
		Type:     "XSS",
		URL:      "http://W3C//DTD",
		Severity: SeverityHigh,
	})
	if err == nil {
		t.Fatal("expected suspicious W3C/DTD artifact URL to be rejected")
	}
}

func TestValidateFindingAllowsInternalServiceHostnames(t *testing.T) {
	cases := []string{
		"http://dvwa/login.php",
		"http://web:8080/admin",
		"http://api.namespace.svc.cluster.local/v1/users",
	}

	for _, rawURL := range cases {
		err := ValidateFinding(&Finding{
			Type:     "Info",
			URL:      rawURL,
			Severity: SeverityInfo,
		})
		if err != nil {
			t.Fatalf("expected internal hostname %q to be allowed, got %v", rawURL, err)
		}
	}
}

func TestValidateFindingSurfaceAllowsConversationalPayloadForLeadOnlyCases(t *testing.T) {
	err := ValidateFindingSurface(&Finding{
		Type:     "Auth",
		URL:      "http://dvwa/login.php",
		Payload:  "Access protected resource without auth header",
		Severity: SeverityHigh,
	})
	if err != nil {
		t.Fatalf("expected surface validation to ignore payload wording, got %v", err)
	}
}
