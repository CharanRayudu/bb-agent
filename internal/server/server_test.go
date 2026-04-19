package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/server"
)

// newTestHandler creates a Server with nil DB — safe for in-memory-only endpoints.
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := &config.Config{
		OpenAIModel:       "gpt-4o",
		OpenAITemperature: 0.1,
	}
	s := server.New(cfg, nil)
	return s.Handler()
}

func do(t *testing.T, h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ── Health ───────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/health", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/health: status=%d, want 200", rr.Code)
	}
}

// ── Schedules (in-memory) ────────────────────────────────────────────────────

func TestSchedulesCRUD(t *testing.T) {
	h := newTestHandler(t)

	// Create
	rr := do(t, h, http.MethodPost, "/api/schedules", map[string]string{
		"target":    "http://example.com",
		"profile":   "quick",
		"cron_expr": "0 2 * * *",
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/schedules: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("POST /api/schedules: response missing 'id'")
	}

	// List
	rr = do(t, h, http.MethodGet, "/api/schedules", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/schedules: status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), id) {
		t.Error("GET /api/schedules: newly created schedule not in list")
	}

	// Delete
	rr = do(t, h, http.MethodDelete, "/api/schedules/"+id, nil)
	if rr.Code != http.StatusOK && rr.Code != http.StatusNoContent {
		t.Errorf("DELETE /api/schedules/%s: status=%d", id, rr.Code)
	}
}

// ── Audit log ────────────────────────────────────────────────────────────────

func TestAuditLog(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/audit", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/audit: status=%d", rr.Code)
	}
	// Must be a JSON array
	var events []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&events); err != nil {
		t.Errorf("GET /api/audit: body is not a JSON array: %v", err)
	}
}

// ── Users / RBAC ─────────────────────────────────────────────────────────────

func TestUsers_CreateAndList(t *testing.T) {
	h := newTestHandler(t)

	rr := do(t, h, http.MethodPost, "/api/users", map[string]string{
		"username": "alice",
		"role":     "admin",
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/users: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	apiKey, _ := resp["api_key"].(string)
	if apiKey == "" {
		t.Error("POST /api/users: response missing 'api_key'")
	}
}

// ── Mutate endpoint ──────────────────────────────────────────────────────────

func TestMutateEndpoint(t *testing.T) {
	h := newTestHandler(t)

	rr := do(t, h, http.MethodPost, "/api/mutate", map[string]string{
		"payload":    "' OR 1=1-- -",
		"vuln_type":  "sqli",
		"tech_stack": "php",
		"waf":        "none",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/mutate: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	variants, ok := resp["variants"]
	if !ok {
		t.Error("POST /api/mutate: response missing 'variants' key")
	}
	varList, _ := variants.([]interface{})
	if len(varList) == 0 {
		t.Error("POST /api/mutate: variants should be non-empty (rule-based fallback)")
	}
}

// ── Remediation list ─────────────────────────────────────────────────────────

func TestRemediationList(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/remediation", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/findings/remediation: status=%d", rr.Code)
	}
	var records []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&records); err != nil {
		t.Errorf("GET /api/findings/remediation: body is not a JSON array: %v", err)
	}
}

// ── CICD Trigger ─────────────────────────────────────────────────────────────

func TestCICDTrigger_NoDBSkip(t *testing.T) {
	// CICD trigger creates a flow which requires DB — skip without a real DB.
	t.Skip("requires PostgreSQL; run with TEST_DATABASE_URL set")
}
