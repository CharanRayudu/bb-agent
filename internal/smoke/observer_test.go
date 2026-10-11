package smoke

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/server"
	"net/http/httptest"
)

type thinkOnlyStub struct{}

func (thinkOnlyStub) Name() string { return "think-only" }

func (thinkOnlyStub) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	prompt := ""
	for _, m := range req.Messages {
		prompt += m.Content
	}
	if strings.Contains(strings.ToLower(prompt), "auditor") {
		return &llm.CompletionResponse{Content: "VALID: TRUE"}, nil
	}
	if strings.Contains(strings.ToLower(prompt), "specialist") {
		return &llm.CompletionResponse{Content: `[{"type":"XSS","priority":"medium","context":"none","target":"http://203.0.113.10/"}]`}, nil
	}
	return &llm.CompletionResponse{
		Content: "",
		ToolCalls: []models.ToolCall{{
			ID: "1", Name: "complete_task", Arguments: `{"summary":"done without scanners"}`,
		}},
	}, nil
}

func TestObserverRefusesSuccessfulCompletionWithoutScanners(t *testing.T) {
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)
	cfg := &config.Config{OpenAIModel: "stub", ExecutionV2: false}
	app := server.New(cfg, db)
	app.UseLLMProvider(thinkOnlyStub{})
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)
	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name": "empty", "description": "no scanners", "target": "http://203.0.113.10/",
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatal(err)
	}
	status := waitForFlowStatus(t, api.URL, flow.ID, models.FlowStatusFailed, 2*time.Minute)
	if status != models.FlowStatusFailed {
		t.Fatalf("status=%s want failed", status)
	}
	_, code := getBodyStatus(t, api.URL+"/api/flows/"+flow.ID.String()+"/report")
	if code != 404 {
		t.Fatalf("report status=%d", code)
	}
}
