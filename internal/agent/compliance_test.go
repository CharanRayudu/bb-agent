package agent

import (
	"strings"
	"testing"
)

func TestComplianceTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		vulnType      string
		wantCWE       string // expected substring in CWE slice
		wantOWASP     string // expected substring in OWASP slice (empty = skip)
		wantNISTNonEmpty bool
		wantPCINonempty  bool
	}{
		{
			name:      "XSS CWE-79 and OWASP A03",
			vulnType:  "XSS",
			wantCWE:   "CWE-79",
			wantOWASP: "A03",
		},
		{
			name:    "SQLi CWE-89",
			vulnType: "SQLi",
			wantCWE:  "CWE-89",
			wantOWASP: "A03",
		},
		{
			name:    "SSRF CWE-918",
			vulnType: "SSRF",
			wantCWE:  "CWE-918",
		},
		{
			name:    "LFI CWE non-empty",
			vulnType: "LFI",
			wantCWE:  "CWE-",
		},
		{
			name:             "JWT NIST non-empty",
			vulnType:         "JWT",
			wantNISTNonEmpty: true,
		},
		{
			name:            "RCE PCI_DSS non-empty",
			vulnType:        "RCE",
			wantPCINonempty: true,
		},
		{
			name:     "Unknown type does not panic",
			vulnType: "some_made_up_vuln_type_99",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Must not panic.
			got := ComplianceTags(tc.vulnType)

			if tc.wantCWE != "" {
				found := false
				for _, cwe := range got.CWE {
					if strings.Contains(cwe, tc.wantCWE) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ComplianceTags(%q).CWE = %v, want entry containing %q",
						tc.vulnType, got.CWE, tc.wantCWE)
				}
			}

			if tc.wantOWASP != "" {
				found := false
				for _, owasp := range got.OWASP {
					if strings.Contains(owasp, tc.wantOWASP) ||
						strings.Contains(strings.ToLower(owasp), "injection") ||
						strings.Contains(strings.ToLower(owasp), "xss") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ComplianceTags(%q).OWASP = %v, want entry containing %q",
						tc.vulnType, got.OWASP, tc.wantOWASP)
				}
			}

			if tc.wantNISTNonEmpty && len(got.NIST) == 0 {
				t.Errorf("ComplianceTags(%q).NIST must not be empty", tc.vulnType)
			}

			if tc.wantPCINonempty && len(got.PCI_DSS) == 0 {
				t.Errorf("ComplianceTags(%q).PCI_DSS must not be empty", tc.vulnType)
			}
		})
	}
}
