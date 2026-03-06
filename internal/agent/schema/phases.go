package schema

import (
	"encoding/json"
	"fmt"
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
	Type     string `json:"type"`               // e.g. "XSS", "SQLi", "SSRF"
	Target   string `json:"target,omitempty"`   // specific endpoint/param
	Context  string `json:"context,omitempty"`  // what the planner observed
	Priority string `json:"priority,omitempty"` // "critical", "high", "medium", "low"
}

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

// ---------------------------------------------------------------------------
// ReconOutput — structured reconnaissance results
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
// FindingsOutput — structured vulnerability findings
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
