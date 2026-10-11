package decision

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFoundryContractChoiceScoreAndNoul(t *testing.T) {
	var gotPath, gotKey, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("api-key")
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"model":"decision-1"`) || !strings.Contains(string(body), `"state"`) || !strings.Contains(string(body), `"questions"`) {
			t.Errorf("request body = %s", body)
		}
		gotModel = "decision-1"
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"model":"decision-1-2026",
			"answers":{
				"specialist":{"type":"choice","choice":"XSS","confidence":0.91,"probabilities":{"XSS":0.91,"SQLi":0.09}},
				"specific":{"type":"noul","noul":0.97},
				"urgency":{"type":"score","score":1.2,"confidence":0.8,"legend":{"0":"low","1":"high"},"probabilities":{"0":0.2,"1":0.8}}
			},
			"usage":{"input_tokens":40,"output_tokens":0}
		}`)
	}))
	defer srv.Close()

	client := NewFoundryClient(srv.URL, "decision-1", "test-key", 2*time.Second)
	resp, err := client.Decide(context.Background(), Request{
		State: map[string]string{"observation": "script in the search parameter"},
		Questions: map[string]Question{
			"specialist": {Type: TypeChoice, Instructions: "Which specialist?", Criteria: map[string]string{"XSS": "script", "SQLi": "sql"}},
			"specific":   {Type: TypeNoul, Instructions: "Is the observation specific?"},
			"urgency":    {Type: TypeScore, Instructions: "How urgent?", Criteria: []string{"low", "high"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != systemOnePath || gotKey != "test-key" || gotModel != "decision-1" {
		t.Fatalf("path=%s key=%s model=%s", gotPath, gotKey, gotModel)
	}
	if resp.Model != "decision-1-2026" || resp.Usage.InputTokens != 40 {
		t.Fatalf("response=%+v", resp)
	}
	choice := resp.Answers["specialist"]
	if choice.Choice != "XSS" || choice.Confidence == nil || *choice.Confidence < 0.9 || !choice.Confident(0.55) {
		t.Fatalf("choice=%+v", choice)
	}
	noul := resp.Answers["specific"]
	if noul.Noul == nil || *noul.Noul != 0.97 {
		t.Fatalf("noul=%+v", noul)
	}
	score := resp.Answers["urgency"]
	if score.Score == nil || *score.Score != 1.2 || score.Legend["1"] != "high" {
		t.Fatalf("score=%+v", score)
	}
	if resp.Latency < 0 {
		t.Fatal("missing latency")
	}
}

func TestFoundryAPIErrorAndCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"detail":[{"loc":["body","questions"],"msg":"field required"}]}`)
	}))
	defer srv.Close()
	client := NewFoundryClient(srv.URL, "decision-1", "test-key", time.Second)
	_, err := client.Decide(context.Background(), Request{Questions: map[string]Question{"q": {Type: TypeNoul}}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 422 || !strings.Contains(apiErr.Error(), "field required") {
		t.Fatalf("err=%v", err)
	}

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer blocked.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := NewFoundryClient(blocked.URL, "decision-1", "test-key", time.Second)
	_, err = slow.Decide(ctx, Request{Questions: map[string]Question{"q": {Type: TypeNoul}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}
