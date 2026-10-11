package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/server"
)

type permanentModelStub struct{}

func (permanentModelStub) Name() string { return "permanent-stub" }

func (permanentModelStub) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, errors.New(`codex API error (HTTP 400): {"detail":"The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account."}`)
}

func TestUnsupportedModelDoesNotCompleteTheScan(t *testing.T) {
	db := openSmokeDB(t)
	prepareSmokeSchema(t, db)
	prepareOrchestratorSchema(t, db)
	cfg := &config.Config{OpenAIModel: "gpt-5.3-codex", ExecutionV2: false}
	app := server.New(cfg, db)
	app.UseLLMProvider(llm.NewGuardedProvider(permanentModelStub{}, llm.Selection{
		Source: "codex_oauth", Model: "gpt-5.3-codex",
	}))
	api := httptest.NewServer(app.Handler())
	t.Cleanup(api.Close)

	created := postJSON(t, api.URL+"/api/flows/create", map[string]string{
		"name": "llm-fail", "description": "unsupported model", "target": "http://203.0.113.10/",
	})
	var flow models.Flow
	if err := json.Unmarshal(created, &flow); err != nil {
		t.Fatal(err)
	}
	status := waitForFlowStatus(t, api.URL, flow.ID, models.FlowStatusFailed, 2*time.Minute)
	if status != models.FlowStatusFailed {
		t.Fatalf("status=%s want failed", status)
	}
	report, code := getBodyStatus(t, fmt.Sprintf("%s/api/flows/%s/report", api.URL, flow.ID))
	if code != 404 {
		t.Fatalf("report status=%d body=%s", code, report)
	}
	if strings.Contains(strings.ToLower(report), "no confirmed vulnerabilities") {
		t.Fatal("failed scan returned a successful assessment report")
	}
}

func getBodyStatus(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	return string(payload), resp.StatusCode
}
