package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// AttackHypothesis is a structured attack hypothesis with confidence and kill-chain context.
type AttackHypothesis struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	VulnClass    string    `json:"vuln_class"`   // e.g. "SQLi", "SSRF", "BusinessLogic"
	Target       string    `json:"target"`        // specific endpoint/param
	Premise      string    `json:"premise"`       // why we believe this is vulnerable
	AttackVector string    `json:"attack_vector"` // how to exploit
	KillChain    []string  `json:"kill_chain"`    // steps from initial access to impact
	Impact       string    `json:"impact"`        // business impact if exploited
	Priority     int       `json:"priority"`      // 1-10, higher=test first
	Confidence   float64   `json:"confidence"`    // 0.0-1.0
	ZeroDayRisk  bool      `json:"zero_day_risk"` // true if pattern suggests novel vuln
	Evidence     []string  `json:"evidence"`      // supporting observations
	GeneratedAt  time.Time `json:"generated_at"`
}

// HypothesisEngine generates prioritized attack hypotheses before specialist dispatch.
type HypothesisEngine struct {
	provider llm.Provider
	model    string
}

// NewHypothesisEngine creates a new HypothesisEngine.
func NewHypothesisEngine(provider llm.Provider, model string) *HypothesisEngine {
	return &HypothesisEngine{provider: provider, model: model}
}

// Generate uses multi-step LLM reasoning to produce attack hypotheses from brain state.
func (h *HypothesisEngine) Generate(ctx context.Context, target string, leads []string, tech *TechStack, existingFindings []*base.Finding) ([]AttackHypothesis, error) {
	if h.provider == nil {
		return h.ruleBasedHypotheses(target, leads, tech), nil
	}

	// Build rich context for reasoning
	techJSON := "{}"
	if tech != nil {
		b, _ := json.Marshal(tech)
		techJSON = string(b)
	}

	leadsSummary := strings.Join(leads, "\n- ")
	existingTypes := make([]string, 0, len(existingFindings))
	for _, f := range existingFindings {
		existingTypes = append(existingTypes, f.Type)
	}

	prompt := fmt.Sprintf(`You are an elite bug bounty hunter performing pre-attack hypothesis generation.

TARGET: %s
TECHNOLOGY PROFILE: %s
RECON LEADS:
- %s
CONFIRMED FINDINGS SO FAR: %v

Your task: Generate prioritized attack hypotheses using multi-step adversarial reasoning.

For each hypothesis, reason through:
1. What observable evidence suggests this attack class?
2. What is the specific target (endpoint, parameter, header)?
3. What kill-chain steps lead from initial trigger to maximum impact?
4. Is this a known vulnerability class or could it be a novel/0-day pattern?
5. What proof would definitively confirm exploitation?

Focus on HIGH-IMPACT findings: RCE, SSRF→cloud-metadata, SQLi→data-exfil, auth-bypass→account-takeover, business-logic→financial-impact.

Respond with a JSON array of hypotheses:
[{
  "title": "short title",
  "vuln_class": "SQLi|XSS|SSRF|RCE|IDOR|BusinessLogic|Deserialization|...",
  "target": "specific endpoint or parameter",
  "premise": "why this endpoint/param is suspicious",
  "attack_vector": "exact technique to test",
  "kill_chain": ["step1", "step2", "step3"],
  "impact": "business impact if successful",
  "priority": 1-10,
  "confidence": 0.0-1.0,
  "zero_day_risk": true/false,
  "evidence": ["observation1", "observation2"]
}]

Generate 5-10 hypotheses ordered by expected impact × confidence.`, target, techJSON, leadsSummary, existingTypes)

	resp, err := h.provider.Complete(ctx, llm.CompletionRequest{
		Model: h.model,
		Messages: []models.ChatMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
	})
	if err != nil {
		return h.ruleBasedHypotheses(target, leads, tech), nil
	}

	// Extract JSON from response
	content := resp.Content
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")
	if start == -1 || end == -1 || end <= start {
		return h.ruleBasedHypotheses(target, leads, tech), nil
	}

	var hypotheses []AttackHypothesis
	if err := json.Unmarshal([]byte(content[start:end+1]), &hypotheses); err != nil {
		return h.ruleBasedHypotheses(target, leads, tech), nil
	}

	// Assign IDs and timestamps
	for i := range hypotheses {
		hypotheses[i].ID = fmt.Sprintf("hyp-%d-%d", time.Now().UnixNano(), i)
		hypotheses[i].GeneratedAt = time.Now()
	}

	// Sort by priority desc
	sort.Slice(hypotheses, func(i, j int) bool {
		return hypotheses[i].Priority > hypotheses[j].Priority
	})

	return hypotheses, nil
}

// RefineSingle refines a hypothesis after specialist attempts, upgrading or downgrading confidence.
func (h *HypothesisEngine) RefineSingle(ctx context.Context, hyp AttackHypothesis, attempt string, succeeded bool) AttackHypothesis {
	if succeeded {
		hyp.Confidence = min64(hyp.Confidence*1.5+0.2, 1.0)
		hyp.Evidence = append(hyp.Evidence, "CONFIRMED: "+attempt)
	} else {
		hyp.Confidence *= 0.7
		hyp.Evidence = append(hyp.Evidence, "FAILED: "+attempt)
	}
	return hyp
}

// ruleBasedHypotheses generates deterministic hypotheses when LLM is unavailable.
func (h *HypothesisEngine) ruleBasedHypotheses(target string, leads []string, tech *TechStack) []AttackHypothesis {
	var hyps []AttackHypothesis

	leadsLower := strings.ToLower(strings.Join(leads, " "))

	// SQL injection hypothesis for database-backed apps
	if tech != nil && (tech.DB != "" || strings.Contains(leadsLower, "sql") || strings.Contains(leadsLower, "id=") || strings.Contains(leadsLower, "query")) {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-sqli-rule", Title: "SQL Injection via ID Parameters",
			VulnClass: "SQLi", Target: target + "?id=1",
			Premise:      "Application uses database; numeric ID parameters detected in recon",
			AttackVector: "Boolean-blind and error-based SQL injection on numeric parameters",
			KillChain:    []string{"Inject quote to trigger error", "Confirm boolean-blind with 1=1 vs 1=2", "Enumerate DB schema", "Dump sensitive tables"},
			Impact:       "Full database read, potential auth bypass, credential theft",
			Priority: 9, Confidence: 0.6, ZeroDayRisk: false,
			Evidence:    []string{"Database tech detected", "ID parameters in URL"},
			GeneratedAt: time.Now(),
		})
	}

	// SSRF hypothesis for services with URL parameters
	if strings.Contains(leadsLower, "url") || strings.Contains(leadsLower, "redirect") || strings.Contains(leadsLower, "fetch") || strings.Contains(leadsLower, "proxy") || strings.Contains(leadsLower, "load") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-ssrf-rule", Title: "SSRF via URL Parameters → Cloud Metadata",
			VulnClass: "SSRF", Target: target,
			Premise:      "URL/redirect parameters detected; application may fetch remote content",
			AttackVector: "Redirect to http://169.254.169.254/latest/meta-data/ to exfil cloud credentials",
			KillChain:    []string{"Identify URL parameter", "Test with internal IP", "Target cloud metadata endpoint", "Extract IAM credentials"},
			Impact:       "Cloud credential theft → full infrastructure compromise",
			Priority: 10, Confidence: 0.65, ZeroDayRisk: false,
			Evidence:    []string{"URL parameters in endpoints"},
			GeneratedAt: time.Now(),
		})
	}

	// IDOR hypothesis
	if strings.Contains(leadsLower, "user") || strings.Contains(leadsLower, "account") || strings.Contains(leadsLower, "profile") || strings.Contains(leadsLower, "order") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-idor-rule", Title: "IDOR via User/Resource Object References",
			VulnClass: "IDOR", Target: target,
			Premise:      "User/account/resource endpoints detected; object reference parameters likely",
			AttackVector: "Enumerate IDs ±1, swap UUIDs between accounts, test horizontal privilege escalation",
			KillChain:    []string{"Create test account", "Identify resource IDs", "Swap to other user IDs", "Access unauthorized data"},
			Impact:       "PII disclosure, account takeover, unauthorized data access",
			Priority: 8, Confidence: 0.55,
			Evidence:    []string{"User/account endpoints detected"},
			GeneratedAt: time.Now(),
		})
	}

	// Auth bypass
	hyps = append(hyps, AttackHypothesis{
		ID: "hyp-authbypass-rule", Title: "Authentication Bypass via Header Manipulation",
		VulnClass: "AuthBypass", Target: target,
		Premise:      "Web application with authentication — common misconfiguration attack surface",
		AttackVector: "Test X-Original-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Admin: true headers",
		KillChain:    []string{"Identify auth-protected endpoints", "Inject IP spoofing headers", "Attempt admin header injection"},
		Impact:       "Authentication bypass → admin access → full system compromise",
		Priority: 7, Confidence: 0.4,
		Evidence:    []string{"Standard web app attack surface"},
		GeneratedAt: time.Now(),
	})

	return hyps
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
