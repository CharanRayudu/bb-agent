package agent

import (
	"strings"
	"testing"
)

func TestAnalyzeTechStack_PHP(t *testing.T) {
	t.Parallel()
	headers := map[string][]string{
		"X-Powered-By": {"PHP/8.1.0"},
	}
	stack := AnalyzeTechStack(headers, "")
	found := false
	for _, c := range stack.Components {
		if strings.Contains(strings.ToLower(c.Name), "php") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PHP header should detect PHP component, got: %+v", stack.Components)
	}
}

func TestAnalyzeTechStack_JavaSessionCookie(t *testing.T) {
	t.Parallel()
	headers := map[string][]string{
		"Set-Cookie": {"JSESSIONID=ABC123DEF; Path=/"},
	}
	stack := AnalyzeTechStack(headers, "")
	found := false
	for _, c := range stack.Components {
		if strings.Contains(strings.ToLower(c.Name), "java") ||
			strings.Contains(strings.ToLower(c.Name), "tomcat") ||
			strings.Contains(strings.ToLower(c.Name), "jsession") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("JSESSIONID cookie should detect Java/Tomcat, got: %+v", stack.Components)
	}
}

func TestAnalyzeTechStack_WordPress(t *testing.T) {
	t.Parallel()
	body := `<link rel='stylesheet' href='https://example.com/wp-content/themes/mytheme/style.css'>`
	stack := AnalyzeTechStack(map[string][]string{}, body)
	found := false
	for _, c := range stack.Components {
		if strings.Contains(strings.ToLower(c.Name), "wordpress") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("wp-content body should detect WordPress, got: %+v", stack.Components)
	}
}

func TestAnalyzeTechStack_EmptyReturnsNoComponents(t *testing.T) {
	t.Parallel()
	stack := AnalyzeTechStack(map[string][]string{}, "")
	// Should not panic; Components may be nil/empty
	_ = stack
}

func TestRecommendSpecialists_PHP(t *testing.T) {
	t.Parallel()
	stack := TechStackAnalysis{
		Components: []TechComponent{
			{Name: "PHP", Category: "language", Confidence: 0.9},
		},
	}
	specs := RecommendSpecialists(stack)
	hasSQLi := false
	hasLFI := false
	for _, s := range specs {
		if s == "sqli" {
			hasSQLi = true
		}
		if s == "lfi" {
			hasLFI = true
		}
	}
	if !hasSQLi {
		t.Errorf("PHP stack should recommend sqli, got: %v", specs)
	}
	if !hasLFI {
		t.Errorf("PHP stack should recommend lfi, got: %v", specs)
	}
}

func TestRecommendSpecialists_Java(t *testing.T) {
	t.Parallel()
	stack := TechStackAnalysis{
		Components: []TechComponent{
			{Name: "Java", Category: "language", Confidence: 0.9},
		},
	}
	specs := RecommendSpecialists(stack)
	hasDeserialization := false
	for _, s := range specs {
		if strings.Contains(s, "deserializ") {
			hasDeserialization = true
			break
		}
	}
	if !hasDeserialization {
		t.Errorf("Java stack should recommend deserialization, got: %v", specs)
	}
}
