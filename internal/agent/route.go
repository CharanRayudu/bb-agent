package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/decision"
)

// SpecialistOption is one label Decision-1 may choose.
type SpecialistOption struct {
	ID          string
	Description string
}

// SpecialistCatalog is the routing label set. "none" means abstain.
var SpecialistCatalog = []SpecialistOption{
	{ID: "XSS", Description: "Reflected, stored, or DOM script injection"},
	{ID: "SQLi", Description: "SQL injection or database error behavior"},
	{ID: "SSRF", Description: "Server-side request or metadata access"},
	{ID: "LFI", Description: "Local file include or path traversal"},
	{ID: "RCE", Description: "Command execution or shell injection"},
	{ID: "IDOR", Description: "Object or account authorization mismatch"},
	{ID: "API Security", Description: "API, JSON, or GraphQL authorization and input"},
	{ID: "Auth Discovery", Description: "Login, session, or credential flow"},
	{ID: "File Upload", Description: "Unrestricted or executable upload"},
	{ID: "Visual Crawler", Description: "Client-rendered SPA route discovery"},
	{ID: "none", Description: "No specialist is justified by this observation"},
}

// RouteResult records which component chose the specialist.
type RouteResult struct {
	Specialist string
	Source     string
	Confidence float64
	Latency    time.Duration
	Reason     string
}

// SetDecisionProvider attaches Decision-1. The generative LLM provider is unchanged.
func (p *Planner) SetDecisionProvider(provider decision.Provider, minConfidence float64) {
	if p == nil {
		return
	}
	if minConfidence <= 0 {
		minConfidence = 0.55
	}
	p.mu.Lock()
	p.decider = provider
	p.minConfidence = minConfidence
	p.mu.Unlock()
}

// SelectSpecialist asks Decision-1 which specialist owns an observation.
// An unavailable or uncertain answer falls back to the deterministic rules.
func (p *Planner) SelectSpecialist(ctx context.Context, observation, target string) RouteResult {
	rules := RuleSpecialist(observation)
	if p == nil || p.decider == nil {
		return RouteResult{Specialist: rules, Source: decision.SourceRules, Reason: "decision provider is not configured"}
	}
	p.mu.RLock()
	provider := p.decider
	minConfidence := p.minConfidence
	p.mu.RUnlock()
	started := time.Now()
	resp, err := provider.Decide(ctx, decision.Request{
		State: map[string]string{
			"observation": observation,
			"target":      target,
		},
		Questions: map[string]decision.Question{
			"specialist": {
				Type:         decision.TypeChoice,
				Instructions: "Which specialist should handle this observation? Choose none when the observation does not justify a specialist.",
				Criteria:     catalogCriteria(),
			},
		},
	})
	latency := time.Since(started)
	if err != nil {
		log.Printf("[planner] Decision-1 unavailable, using deterministic specialist rules: %v", err)
		return RouteResult{Specialist: rules, Source: decision.SourceRules, Latency: latency, Reason: err.Error()}
	}
	answer, ok := resp.Answers["specialist"]
	if !ok || answer.Type != decision.TypeChoice || !answer.Confident(minConfidence) || answer.Choice == "" || answer.Choice == "none" || !knownSpecialist(answer.Choice) {
		reason := "decision was uncertain"
		if ok && answer.Choice != "" {
			reason = "decision chose " + answer.Choice
		}
		return RouteResult{Specialist: rules, Source: decision.SourceRules, Latency: resp.Latency, Reason: reason}
	}
	confidence := 0.0
	if answer.Confidence != nil {
		confidence = *answer.Confidence
	}
	return RouteResult{Specialist: answer.Choice, Source: decision.SourceModel, Confidence: confidence, Latency: resp.Latency}
}

const decisionBatchSize = 8

// RouteSpecs asks Decision-1 about a batch of observations in one request.
// An unavailable or uncertain answer leaves that spec's specialist unchanged.
func (p *Planner) RouteSpecs(ctx context.Context, specs []SwarmAgentSpec) []SwarmAgentSpec {
	if p == nil || p.decider == nil || len(specs) == 0 {
		return specs
	}
	out := append([]SwarmAgentSpec(nil), specs...)
	p.mu.RLock()
	provider := p.decider
	minConfidence := p.minConfidence
	p.mu.RUnlock()
	for start := 0; start < len(out); start += decisionBatchSize {
		end := start + decisionBatchSize
		if end > len(out) {
			end = len(out)
		}
		p.routeBatch(ctx, provider, minConfidence, out[start:end])
	}
	return out
}

func (p *Planner) routeBatch(ctx context.Context, provider decision.Provider, minConfidence float64, specs []SwarmAgentSpec) {
	questions := make(map[string]decision.Question, len(specs))
	observations := make([]map[string]string, len(specs))
	for i := range specs {
		id := fmt.Sprintf("s%d", i)
		text := strings.TrimSpace(strings.Join([]string{specs[i].Type, specs[i].Context, specs[i].Hypothesis}, "\n"))
		observations[i] = map[string]string{"id": id, "text": text, "target": specs[i].Target}
		questions[id] = decision.Question{
			Type:         decision.TypeChoice,
			Instructions: "Which specialist should handle observation " + id + "? Choose none when it does not justify a specialist.",
			Criteria:     catalogCriteria(),
		}
	}
	started := time.Now()
	resp, err := provider.Decide(ctx, decision.Request{
		State:     map[string]any{"observations": observations},
		Questions: questions,
	})
	latency := time.Since(started)
	if resp.Latency > 0 {
		latency = resp.Latency
	}
	if err != nil {
		log.Printf("[planner] Decision-1 batch unavailable, keeping current specialist labels: %v", err)
		for i := range specs {
			specs[i].DecisionSource = decision.SourceRules
			specs[i].DecisionLatencyMS = latency.Milliseconds()
			specs[i].DecisionReason = err.Error()
		}
		return
	}
	for i := range specs {
		id := fmt.Sprintf("s%d", i)
		answer, ok := resp.Answers[id]
		rules := RuleSpecialist(observations[i]["text"])
		specs[i].DecisionLatencyMS = latency.Milliseconds()
		if !ok || answer.Type != decision.TypeChoice || !answer.Confident(minConfidence) || answer.Choice == "" || answer.Choice == "none" || !knownSpecialist(answer.Choice) {
			specs[i].DecisionSource = decision.SourceRules
			specs[i].DecisionReason = "decision was uncertain"
			if ok && answer.Choice != "" {
				specs[i].DecisionReason = "decision chose " + answer.Choice
			}
			if rules != "" && specs[i].Type == "" {
				specs[i].Type = rules
			}
			continue
		}
		confidence := 0.0
		if answer.Confidence != nil {
			confidence = *answer.Confidence
		}
		specs[i].Type = answer.Choice
		specs[i].DecisionSource = decision.SourceModel
		specs[i].DecisionConfidence = confidence
		specs[i].DecisionReason = ""
	}
}

// RuleSpecialist is the deterministic specialist label for one observation.
// An empty result means the keyword rules do not name a specialist.
func RuleSpecialist(observation string) string {
	note := strings.ToLower(normalizeBrainNote(observation))
	switch {
	case strings.Contains(note, "login"), strings.Contains(note, "auth"), strings.Contains(note, "credential"):
		return "Auth Discovery"
	case strings.Contains(note, "/api"), strings.Contains(note, "json"), strings.Contains(note, "graphql"):
		return "API Security"
	case strings.Contains(note, "upload"):
		return "File Upload"
	case strings.Contains(note, "xss"), strings.Contains(note, "script"), strings.Contains(note, "dom"):
		return "XSS"
	case strings.Contains(note, "sqli"), strings.Contains(note, "sql"), strings.Contains(note, "database"):
		return "SQLi"
	case strings.Contains(note, "ssrf"), strings.Contains(note, "metadata"), strings.Contains(note, "callback"):
		return "SSRF"
	case strings.Contains(note, "include"), strings.Contains(note, "passwd"), strings.Contains(note, "traversal"), strings.Contains(note, "lfi"):
		return "LFI"
	case strings.Contains(note, "exec"), strings.Contains(note, "command"), strings.Contains(note, "shell"), strings.Contains(note, "rce"):
		return "RCE"
	case strings.Contains(note, "idor"), strings.Contains(note, "object id"), strings.Contains(note, "profile"), strings.Contains(note, "account"):
		return "IDOR"
	case strings.Contains(note, "spa"), strings.Contains(note, "react"), strings.Contains(note, "vue"), strings.Contains(note, "angular"):
		return "Visual Crawler"
	default:
		return ""
	}
}

func catalogCriteria() map[string]string {
	out := make(map[string]string, len(SpecialistCatalog))
	for _, option := range SpecialistCatalog {
		out[option.ID] = option.Description
	}
	return out
}

func knownSpecialist(id string) bool {
	for _, option := range SpecialistCatalog {
		if option.ID == id {
			return true
		}
	}
	return false
}
