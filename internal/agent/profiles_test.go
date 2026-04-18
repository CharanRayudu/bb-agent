package agent

import (
	"testing"
)

func TestGetProfile_KnownProfiles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		wantMinSpecialists int
		wantMinTimeout  bool
		wantAggressive  int
	}{
		{"quick", 1, true, 0},
		{"owasp", 3, true, 0},
		{"api", 1, true, 0},
		{"pci", 1, true, 0},
		{"stealth", 1, true, 0},
		{"full", 1, true, 5},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, ok := GetProfile(tc.name)
			if !ok {
				t.Fatalf("GetProfile(%q) returned ok=false", tc.name)
			}
			if len(p.Specialists) < tc.wantMinSpecialists {
				t.Errorf("profile %q: len(Specialists)=%d, want >=%d", tc.name, len(p.Specialists), tc.wantMinSpecialists)
			}
			if tc.wantMinTimeout && p.Timeout <= 0 {
				t.Errorf("profile %q: Timeout should be > 0", tc.name)
			}
			if tc.wantAggressive > 0 && p.Aggressiveness != tc.wantAggressive {
				t.Errorf("profile %q: Aggressiveness=%d, want %d", tc.name, p.Aggressiveness, tc.wantAggressive)
			}
		})
	}
}

func TestGetProfile_Unknown(t *testing.T) {
	t.Parallel()
	_, ok := GetProfile("nonexistent_profile_xyz")
	if ok {
		t.Error("GetProfile with unknown name should return ok=false")
	}
}

func TestGetProfile_OWASPHasXSSAndSQLi(t *testing.T) {
	t.Parallel()
	p, ok := GetProfile("owasp")
	if !ok {
		t.Fatal("owasp profile must exist")
	}
	hasXSS, hasSQLi := false, false
	for _, s := range p.Specialists {
		if s == "xss" {
			hasXSS = true
		}
		if s == "sqli" {
			hasSQLi = true
		}
	}
	if !hasXSS {
		t.Error("owasp profile should include xss specialist")
	}
	if !hasSQLi {
		t.Error("owasp profile should include sqli specialist")
	}
}

func TestDefaultProfiles_AllSixExist(t *testing.T) {
	t.Parallel()
	required := []string{"quick", "owasp", "api", "pci", "stealth", "full"}
	for _, name := range required {
		if _, ok := DefaultProfiles[name]; !ok {
			t.Errorf("DefaultProfiles missing required profile: %q", name)
		}
	}
}
