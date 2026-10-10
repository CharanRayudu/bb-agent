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

func (s scriptDecision) Decide(ctx context.Context, _ decision.Request) (decision.Response, error) {
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
	return s.response, nil
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
