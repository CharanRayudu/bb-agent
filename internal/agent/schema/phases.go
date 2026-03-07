package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Phase-Specific Output Schemas
// ---------------------------------------------------------------------------

// PlannerOutput is the expected output from the Thinking & Consolidation phase.
// The planner dispatches specialist agents based on recon findings.
type PlannerOutput struct {
	Specs []AgentSpec `json:"specs"`
}

// AgentSpec describes a single specialist agent dispatch.
type AgentSpec struct {
	Type         string `json:"type"`                    // e.g. "XSS", "SQLi", "SSRF"
	Target       string `json:"target,omitempty"`        // specific endpoint/param
	Context      string `json:"context,omitempty"`       // what the planner observed
	Hypothesis   string `json:"hypothesis,omitempty"`    // focused attack-path hypothesis
	Proof        string `json:"proof,omitempty"`         // proof required for promotion
	RequiresAuth bool   `json:"requires_auth,omitempty"` // whether auth continuity matters
	AuthContext  string `json:"auth_context,omitempty"`  // auth notes/cookies/tokens to preserve
	Priority     string `json:"priority,omitempty"`      // "critical", "high", "medium", "low"
}

var plannerTypePatterns = []struct {
	canonical string
	re        *regexp.Regexp
}{
	{canonical: "XSS", re: regexp.MustCompile(`(?i)\b(?:xss|cross[\s-]?site scripting)\b`)},
	{canonical: "SQLi", re: regexp.MustCompile(`(?i)\b(?:sqli|sql injection)\b`)},
	{canonical: "SSRF", re: regexp.MustCompile(`(?i)\b(?:ssrf|server[\s-]?side request forgery)\b`)},
	{canonical: "LFI", re: regexp.MustCompile(`(?i)\b(?:lfi|local file inclusion|path traversal)\b`)},
	{canonical: "RCE", re: regexp.MustCompile(`(?i)\b(?:rce|remote code execution|command injection)\b`)},
	{canonical: "XXE", re: regexp.MustCompile(`(?i)\b(?:xxe|xml external entity)\b`)},
	{canonical: "OpenRedirect", re: regexp.MustCompile(`(?i)\bopen redirect\b`)},
	{canonical: "IDOR", re: regexp.MustCompile(`(?i)\b(?:idor|insecure direct object reference)\b`)},
	{canonical: "CSTI", re: regexp.MustCompile(`(?i)\b(?:csti|ssti|template injection)\b`)},
	{canonical: "JWT", re: regexp.MustCompile(`(?i)\bjwt\b`)},
	{canonical: "FileUpload", re: regexp.MustCompile(`(?i)\bfile upload\b`)},
	{canonical: "APISecurity", re: regexp.MustCompile(`(?i)\bapi security\b`)},
	{canonical: "BusinessLogic", re: regexp.MustCompile(`(?i)\bbusiness logic\b`)},
}

var plannerURLHintRe = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|/[A-Za-z0-9._~!$&()*+,;=:@%/\-?#[\]]+)`)

// Validate ensures the planner output is well-formed.
func (p *PlannerOutput) Validate() error {
	if len(p.Specs) == 0 {
		return fmt.Errorf("planner must dispatch at least 1 specialist agent")
	}
	for i, spec := range p.Specs {
		if spec.Type == "" {
			return fmt.Errorf("spec[%d]: missing required field 'type'", i)
		}
		// Normalize priority
		if spec.Priority == "" {
			p.Specs[i].Priority = "medium"
		}
	}
	return nil
}

// ParsePlannerOutput accepts both the canonical object form and a bare array of AgentSpec values.
func ParsePlannerOutput(raw string) (PlannerOutput, error) {
	result, err := Parse[PlannerOutput](raw)
	if err == nil {
		return result, nil
	}

	jsonStr := ExtractJSON(raw)
	if jsonStr == "" {
		if repaired, ok := parsePlannerOutputFromProse(raw); ok {
			return repaired, nil
		}
		return PlannerOutput{}, err
	}

	var specs []AgentSpec
	if arrayErr := json.Unmarshal([]byte(jsonStr), &specs); arrayErr == nil {
		repaired := PlannerOutput{Specs: specs}
		if validateErr := repaired.Validate(); validateErr != nil {
			return PlannerOutput{}, fmt.Errorf("schema validation failed: %s. Fix the issue and return corrected JSON", validateErr.Error())
		}
		return repaired, nil
	}

	var alt struct {
		Specs       []AgentSpec `json:"specs"`
		Agents      []AgentSpec `json:"agents"`
		Specialists []AgentSpec `json:"specialists"`
		Dispatch    []AgentSpec `json:"dispatch"`
	}
	if altErr := json.Unmarshal([]byte(jsonStr), &alt); altErr == nil {
		switch {
		case len(alt.Agents) > 0:
			alt.Specs = alt.Agents
		case len(alt.Specialists) > 0:
			alt.Specs = alt.Specialists
		case len(alt.Dispatch) > 0:
			alt.Specs = alt.Dispatch
		}
		if len(alt.Specs) > 0 {
			repaired := PlannerOutput{Specs: alt.Specs}
			if validateErr := repaired.Validate(); validateErr != nil {
				return PlannerOutput{}, fmt.Errorf("schema validation failed: %s. Fix the issue and return corrected JSON", validateErr.Error())
			}
			return repaired, nil
		}
	}

	return PlannerOutput{}, err
}

func parsePlannerOutputFromProse(raw string) (PlannerOutput, bool) {
	lines := strings.Split(raw, "\n")
	specsByType := make(map[string]AgentSpec)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, pattern := range plannerTypePatterns {
			if !pattern.re.MatchString(line) {
				continue
			}

			spec := specsByType[pattern.canonical]
			spec.Type = pattern.canonical
			if spec.Target == "" {
				spec.Target = extractPlannerURLHint(line)
			}
			if spec.Context == "" {
				spec.Context = line
			}
			spec.Priority = mergePlannerPriority(spec.Priority, extractPlannerPriority(line))
			specsByType[pattern.canonical] = spec
		}
	}

	if len(specsByType) == 0 {
		for _, pattern := range plannerTypePatterns {
			if !pattern.re.MatchString(raw) {
				continue
			}
			specsByType[pattern.canonical] = AgentSpec{
				Type:     pattern.canonical,
				Target:   extractPlannerURLHint(raw),
				Context:  strings.TrimSpace(raw),
				Priority: extractPlannerPriority(raw),
			}
		}
	}

	if len(specsByType) == 0 {
		return PlannerOutput{}, false
	}

	specs := make([]AgentSpec, 0, len(specsByType))
	for _, spec := range specsByType {
		if spec.Priority == "" {
			spec.Priority = "medium"
		}
		specs = append(specs, spec)
	}

	repaired := PlannerOutput{Specs: specs}
	if err := repaired.Validate(); err != nil {
		return PlannerOutput{}, false
	}
	return repaired, true
}

func extractPlannerPriority(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "critical"):
		return "critical"
	case strings.Contains(lower, "high"):
		return "high"
	case strings.Contains(lower, "medium"):
		return "medium"
	case strings.Contains(lower, "low"):
		return "low"
	default:
		return ""
	}
}

func mergePlannerPriority(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}

	rank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}
	if rank[next] > rank[existing] {
		return next
	}
	return existing
}

func extractPlannerURLHint(raw string) string {
	return strings.TrimSpace(plannerURLHintRe.FindString(raw))
}

// ---------------------------------------------------------------------------
// ReconOutput â€” structured reconnaissance results
// ---------------------------------------------------------------------------

// ReconOutput is the expected output from the Reconnaissance phase.
type ReconOutput struct {
	Leads     []string   `json:"leads"`                // Discovered attack surface leads
	Endpoints []Endpoint `json:"endpoints,omitempty"`  // Discovered HTTP endpoints
	TechHints []string   `json:"tech_hints,omitempty"` // Technology indicators
	Summary   string     `json:"summary,omitempty"`    // Human-readable summary
}

// Endpoint represents a discovered HTTP endpoint.
type Endpoint struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	InputType  string `json:"input_type,omitempty"` // query, body, header, cookie
	AuthNeeded bool   `json:"auth_needed,omitempty"`
}

// Validate ensures recon output has useful content.
func (r *ReconOutput) Validate() error {
	if len(r.Leads) == 0 && len(r.Endpoints) == 0 {
		return fmt.Errorf("recon must produce at least 1 lead or endpoint")
	}
	for i, ep := range r.Endpoints {
		if ep.URL == "" {
			return fmt.Errorf("endpoint[%d]: missing required field 'url'", i)
		}
		if !strings.HasPrefix(ep.URL, "http://") && !strings.HasPrefix(ep.URL, "https://") {
			return fmt.Errorf("endpoint[%d]: invalid URL scheme: %s", i, ep.URL)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// FindingsOutput â€” structured vulnerability findings
// ---------------------------------------------------------------------------

// FindingsOutput is the expected output from specialist agents and PoC phases.
type FindingsOutput struct {
	Findings []FindingSpec `json:"findings"`
}

// FindingSpec is a schema-level finding (lighter than base.Finding, used for validation).
type FindingSpec struct {
	Type       string  `json:"type"`                 // XSS, SQLi, SSRF, etc.
	URL        string  `json:"url"`                  // Target URL
	Parameter  string  `json:"parameter,omitempty"`  // Vulnerable parameter
	Payload    string  `json:"payload,omitempty"`    // Triggering payload
	Severity   string  `json:"severity"`             // critical, high, medium, low, info
	Confidence float64 `json:"confidence,omitempty"` // 0.0 - 1.0
	Method     string  `json:"method,omitempty"`     // GET, POST, etc.
	Evidence   string  `json:"evidence,omitempty"`   // Supporting evidence
}

// Validate ensures findings are well-formed.
func (f *FindingsOutput) Validate() error {
	for i, finding := range f.Findings {
		if finding.Type == "" {
			return fmt.Errorf("finding[%d]: missing required field 'type'", i)
		}
		if finding.URL == "" {
			return fmt.Errorf("finding[%d]: missing required field 'url'", i)
		}
		if !strings.HasPrefix(finding.URL, "http://") && !strings.HasPrefix(finding.URL, "https://") {
			return fmt.Errorf("finding[%d]: invalid URL scheme: %s", i, finding.URL)
		}
		if finding.Severity == "" {
			return fmt.Errorf("finding[%d]: missing required field 'severity'", i)
		}
	}
	return nil
}
