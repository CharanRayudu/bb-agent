package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/decision"
)

type scriptDecision struct {
	response decision.Response
	err      error
	wait     time.Duration
}

func (s scriptDecision) Decide(ctx context.Context, req decision.Request) (decision.Response, error) {
	if s.wait > 0 {
		timer := time.NewTimer(s.wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return decision.Response{}, ctx.Err()
		case <-timer.C:
		}
	}
	if s.err != nil {
		return decision.Response{}, s.err
	}
	resp := s.response
	if len(req.Questions) == 0 || len(resp.Answers) == 0 {
		return resp, nil
	}
	var seed decision.Answer
	for _, answer := range resp.Answers {
		seed = answer
		break
	}
	resp.Answers = make(map[string]decision.Answer, len(req.Questions))
	for id := range req.Questions {
		resp.Answers[id] = seed
	}
	return resp, nil
}

func choiceResponse(label string, confidence float64, latency time.Duration) decision.Response {
	return decision.Response{
		Model:   "decision-1",
		Latency: latency,
		Answers: map[string]decision.Answer{
			"specialist": {Type: decision.TypeChoice, Choice: label, Confidence: &confidence},
		},
	}
}

func TestDecisionRoutingAgainstDeterministicRules(t *testing.T) {
	cases := []struct {
		name        string
		observation string
		provider    decision.Provider
		want        string
		wantSource  string
	}{
		{
			name:        "confident agreement",
			observation: "reflected script in the search box",
			provider:    scriptDecision{response: choiceResponse("XSS", 0.93, 12*time.Millisecond), wait: 5 * time.Millisecond},
			want:        "XSS",
			wantSource:  decision.SourceModel,
		},
		{
			name:        "confident disagreement",
			observation: "reflected script in the search box",
			provider:    scriptDecision{response: choiceResponse("SQLi", 0.91, 8*time.Millisecond)},
			want:        "SQLi",
			wantSource:  decision.SourceModel,
		},
		{
			name:        "uncertain keeps the rule",
			observation: "sql error from the search query",
			provider:    scriptDecision{response: choiceResponse("SSRF", 0.31, 4*time.Millisecond)},
			want:        "SQLi",
			wantSource:  decision.SourceRules,
		},
		{
			name:        "api failure keeps the rule",
			observation: "file upload of an executable",
			provider:    scriptDecision{err: &decision.APIError{Status: 503, Detail: "unavailable"}},
			want:        "File Upload",
			wantSource:  decision.SourceRules,
		},
		{
			name:        "abstain keeps the rule",
			observation: "metadata callback from the image fetcher",
			provider:    scriptDecision{response: choiceResponse("none", 0.8, time.Millisecond)},
			want:        "SSRF",
			wantSource:  decision.SourceRules,
		},
	}

	var agreed, disagreed, failed int
	var latency time.Duration
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			planner := NewPlanner(nil, nil, nil)
			planner.SetDecisionProvider(tc.provider, 0.55)
			got := planner.SelectSpecialist(context.Background(), tc.observation, "http://app.example")
			if got.Specialist != tc.want || got.Source != tc.wantSource {
				t.Fatalf("got %+v", got)
			}
			rules := RuleSpecialist(tc.observation)
			latency += got.Latency
			switch {
			case got.Source == decision.SourceRules && got.Reason != "" && tc.wantSource == decision.SourceRules && tc.name == "api failure keeps the rule":
				failed++
			case got.Specialist == rules:
				agreed++
			default:
				disagreed++
			}
			if got.Source == decision.SourceModel && got.Confidence < 0.55 {
				t.Fatal("confident route stored a low confidence")
			}
		})
	}
	if agreed == 0 || disagreed == 0 || failed == 0 {
		t.Fatalf("comparison did not cover agreement, disagreement, and failure: agreed=%d disagreed=%d failed=%d latency=%s", agreed, disagreed, failed, latency)
	}
}

func TestOrchestratorInvokesDecisionRouting(t *testing.T) {
	orch := &Orchestrator{}
	planner := NewPlanner(nil, nil, nil)
	planner.SetDecisionProvider(scriptDecision{response: choiceResponse("SQLi", 0.96, 3*time.Millisecond)}, 0.55)
	orch.SetDecisionPlanner(planner)
	got := orch.routeSpecialists(context.Background(), []SwarmAgentSpec{{
		Type:    "Visual Crawler",
		Context: "script in the search parameter",
		Target:  "http://app.example/search",
	}})
	if len(got) != 1 || got[0].Type != "SQLi" || got[0].DecisionSource != decision.SourceModel || got[0].DecisionConfidence < 0.9 {
		t.Fatalf("orchestrator routing=%+v", got)
	}
}

func TestRoutingCostWhenEnabledDisabledAndUnavailable(t *testing.T) {
	specs := make([]SwarmAgentSpec, 5)
	for i := range specs {
		specs[i] = SwarmAgentSpec{Type: "Visual Crawler", Context: "spa route", Target: "http://app.example"}
	}
	disabled := NewPlanner(nil, nil, nil)
	disabledStarted := time.Now()
	disabledGot := disabled.RouteSpecs(context.Background(), specs)
	disabledLatency := time.Since(disabledStarted)
	if disabledGot[0].Type != "Visual Crawler" || disabledGot[0].DecisionSource != "" {
		t.Fatalf("disabled routing changed the spec: %+v", disabledGot[0])
	}

	enabledCounter := &countingDecision{delay: 20 * time.Millisecond, choice: "XSS", confidence: 0.91}
	enabled := NewPlanner(nil, nil, nil)
	enabled.SetDecisionProvider(enabledCounter, 0.55)
	enabledStarted := time.Now()
	enabledGot := enabled.RouteSpecs(context.Background(), specs)
	enabledLatency := time.Since(enabledStarted)
	if enabledCounter.calls != 1 {
		t.Fatalf("enabled calls=%d, want one batched request", enabledCounter.calls)
	}
	if enabledGot[4].Type != "XSS" || enabledGot[4].DecisionSource != decision.SourceModel {
		t.Fatalf("enabled routing=%+v", enabledGot[4])
	}

	downCounter := &countingDecision{err: errors.New("foundry unavailable")}
	down := NewPlanner(nil, nil, nil)
	down.SetDecisionProvider(downCounter, 0.55)
	downGot := down.RouteSpecs(context.Background(), specs)
	if downCounter.calls != 1 || downGot[0].Type != "Visual Crawler" || downGot[0].DecisionSource != decision.SourceRules {
		t.Fatalf("unavailable calls=%d routing=%+v", downCounter.calls, downGot[0])
	}
	if enabledLatency < 15*time.Millisecond || disabledLatency > enabledLatency {
		t.Fatalf("latency disabled=%s enabled=%s", disabledLatency, enabledLatency)
	}
}

type countingDecision struct {
	calls      int
	delay      time.Duration
	err        error
	choice     string
	confidence float64
}

func (c *countingDecision) Decide(ctx context.Context, req decision.Request) (decision.Response, error) {
	c.calls++
	if c.delay > 0 {
		timer := time.NewTimer(c.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return decision.Response{}, ctx.Err()
		case <-timer.C:
		}
	}
	if c.err != nil {
		return decision.Response{}, c.err
	}
	answers := make(map[string]decision.Answer, len(req.Questions))
	confidence := c.confidence
	for id := range req.Questions {
		answers[id] = decision.Answer{Type: decision.TypeChoice, Choice: c.choice, Confidence: &confidence}
	}
	return decision.Response{Model: "decision-1", Latency: c.delay, Answers: answers}, nil
}

func TestRouteSpecsLeavesGenerativeChoiceWhenDecisionIsDown(t *testing.T) {
	planner := NewPlanner(nil, nil, nil)
	planner.SetDecisionProvider(scriptDecision{err: errors.New("connection refused")}, 0.55)
	specs := planner.RouteSpecs(context.Background(), []SwarmAgentSpec{{
		Type:    "Reflected XSS",
		Context: "parameter reflects input",
		Target:  "http://app.example/search",
	}})
	if specs[0].Type != "Reflected XSS" {
		t.Fatalf("fallback replaced the generative specialist: %+v", specs[0])
	}
}
