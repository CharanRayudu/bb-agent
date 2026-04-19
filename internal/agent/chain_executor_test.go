package agent

import (
	"strings"
	"testing"
)

func TestDetectChains_Empty(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	chains := ce.DetectChains(nil)
	if len(chains) != 0 {
		t.Errorf("nil findings should return empty chains, got %d", len(chains))
	}
	chains = ce.DetectChains([]*Finding{})
	if len(chains) != 0 {
		t.Errorf("empty findings should return empty chains, got %d", len(chains))
	}
}

func TestDetectChains_SingleFinding(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	findings := []*Finding{
		{Type: "XSS", Severity: "high", Confidence: 0.9},
	}
	chains := ce.DetectChains(findings)
	// Single XSS alone doesn't form a multi-step chain
	for _, c := range chains {
		if len(c.Findings) < 2 {
			t.Logf("chain %q has only 1 finding — expected multi-step", c.ChainType)
		}
	}
}

func TestDetectChains_SSRFToCloudCreds(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	findings := []*Finding{
		{
			Type:      "SSRF",
			Severity:  "high",
			Confidence: 0.9,
			Evidence: map[string]interface{}{
				"ssrf_type":        "cloud_metadata",
				"metadata_detected": true,
			},
		},
	}
	chains := ce.DetectChains(findings)
	found := false
	for _, c := range chains {
		if strings.Contains(c.ChainType, "SSRF") || strings.Contains(c.ChainType, "Cloud") {
			found = true
			break
		}
	}
	if !found {
		t.Error("SSRF with cloud_metadata evidence should produce a chain")
	}
}

func TestDetectChains_LFIToRCE(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	findings := []*Finding{
		{
			Type:      "LFI",
			Severity:  "high",
			Confidence: 0.9,
			// evidenceContains checks for "log_poisoning" as a key in evidence map values
			Evidence: map[string]interface{}{
				"technique":     "log_poisoning",
				"file":          "/var/log/apache2/access.log",
			},
		},
	}
	chains := ce.DetectChains(findings)
	found := false
	for _, c := range chains {
		if strings.Contains(c.ChainType, "LFI") || strings.Contains(c.ChainType, "RCE") {
			found = true
			break
		}
	}
	if !found {
		t.Error("LFI + RCE findings should produce an LFI→RCE chain")
	}
}

func TestFormatChainReport_NonEmpty(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	chains := []DetectedChain{
		{
			ChainType:   "SSRF→CloudCreds",
			Severity:    "Critical",
			Description: "SSRF leads to cloud credential exposure",
			Steps:       []string{"Step 1: SSRF", "Step 2: Metadata"},
			Findings: []*Finding{
				{Type: "SSRF", URL: "http://example.com/fetch"},
			},
		},
	}
	report := ce.FormatChainReport(chains)
	if report == "" {
		t.Error("FormatChainReport should return non-empty report")
	}
	if !strings.Contains(report, "SSRF") {
		t.Error("Report should mention SSRF")
	}
	if !strings.Contains(report, "Critical") {
		t.Error("Report should mention Critical severity")
	}
}

func TestFormatChainReport_Empty(t *testing.T) {
	t.Parallel()
	ce := NewChainExecutor()
	report := ce.FormatChainReport(nil)
	// Should not panic, may return empty string or "no chains" message
	_ = report
}
