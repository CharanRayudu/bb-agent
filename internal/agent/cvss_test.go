package agent

import (
	"strings"
	"testing"
)

func TestCVSS_ScoreFinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		findingType  string
		wantMinScore float64
		wantMaxScore float64
		wantSeverity string
	}{
		{
			name:         "SQLi critical score",
			findingType:  "sqli",
			wantMinScore: 9.0,
			wantMaxScore: 10.0,
			wantSeverity: "Critical",
		},
		{
			name:         "XSS reflected medium range",
			findingType:  "xss (reflected)",
			wantMinScore: 5.0,
			wantMaxScore: 8.0,
			wantSeverity: "",
		},
		{
			name:         "SSRF cloud metadata critical",
			findingType:  "ssrf (cloud metadata)",
			wantMinScore: 9.5,
			wantMaxScore: 10.0,
			wantSeverity: "Critical",
		},
		{
			name:         "RCE near 10",
			findingType:  "rce",
			wantMinScore: 9.0,
			wantMaxScore: 10.0,
			wantSeverity: "Critical",
		},
		{
			name:         "Unknown type returns non-zero default",
			findingType:  "totally_unknown_vuln_type",
			wantMinScore: 0.1,
			wantMaxScore: 10.0,
			wantSeverity: "",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &Finding{Type: tc.findingType}
			got := ScoreFinding(f)

			if got.Score < tc.wantMinScore || got.Score > tc.wantMaxScore {
				t.Errorf("ScoreFinding(%q).Score = %v, want in [%v, %v]",
					tc.findingType, got.Score, tc.wantMinScore, tc.wantMaxScore)
			}
			if tc.wantSeverity != "" && got.Severity != tc.wantSeverity {
				t.Errorf("ScoreFinding(%q).Severity = %q, want %q",
					tc.findingType, got.Severity, tc.wantSeverity)
			}
			if got.Score == 0 {
				t.Errorf("ScoreFinding(%q).Score must be non-zero", tc.findingType)
			}
		})
	}
}

func TestCVSS_RemediationFor(t *testing.T) {
	t.Parallel()

	t.Run("SQLi has non-empty summary and steps and references", func(t *testing.T) {
		t.Parallel()
		r := RemediationFor("sqli")
		if r.Summary == "" {
			t.Error("RemediationFor(sqli).Summary must not be empty")
		}
		if len(r.Steps) == 0 {
			t.Error("RemediationFor(sqli).Steps must have at least one step")
		}
		if len(r.References) == 0 {
			t.Error("RemediationFor(sqli).References must have at least one reference")
		}
	})

	t.Run("XSS steps contain CSP or encode", func(t *testing.T) {
		t.Parallel()
		r := RemediationFor("xss")
		if len(r.Steps) == 0 {
			t.Fatal("RemediationFor(xss).Steps must not be empty")
		}
		found := false
		for _, step := range r.Steps {
			lower := strings.ToLower(step)
			if strings.Contains(lower, "content-security-policy") || strings.Contains(lower, "encode") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RemediationFor(xss).Steps should contain 'Content-Security-Policy' or 'encode', got: %v", r.Steps)
		}
	})

	t.Run("Unknown type returns non-zero Remediation", func(t *testing.T) {
		t.Parallel()
		r := RemediationFor("totally_unknown_vuln_xyz")
		if r.Summary == "" && len(r.Steps) == 0 && len(r.References) == 0 {
			t.Error("RemediationFor(unknown) must return a non-zero Remediation")
		}
	})
}
