package server_test

// TestUserFlow_FullJourney simulates the complete path a user takes through the
// API surface without a real database:
//
//  1. Register a user (RBAC) and receive an API key
//  2. Create a scheduled scan → verify it appears in the list
//  3. Delete the scheduled scan → verify it's gone
//  4. POST /api/mutate to get payload variants for a SQL-injection payload
//  5. GET /api/findings/remediation → verify it returns a JSON array
//  6. GET /api/audit → verify it returns a JSON array (events accumulate)
//  7. Health-check sanity at the end
//
// All subsystems (RBAC, Scheduler, AuditLog, RemediationTracker) are in-memory
// so no PostgreSQL connection is required.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestUserFlow_FullJourney(t *testing.T) {
	h := newTestHandler(t)

	// ── Step 1: Register user ────────────────────────────────────────────────
	rr := do(t, h, http.MethodPost, "/api/users", map[string]string{
		"username": "pentester",
		"role":     "admin",
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("step1 POST /api/users: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var userResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&userResp)
	apiKey, _ := userResp["api_key"].(string)
	if apiKey == "" {
		t.Fatal("step1: response missing api_key")
	}
	t.Logf("step1: user created, api_key prefix=%s...", apiKey[:min(8, len(apiKey))])

	// ── Step 2: Create a scheduled scan ─────────────────────────────────────
	rr = do(t, h, http.MethodPost, "/api/schedules", map[string]string{
		"target":    "https://target.example.com",
		"profile":   "owasp",
		"cron_expr": "0 3 * * *",
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("step2 POST /api/schedules: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var schedResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&schedResp)
	schedID, _ := schedResp["id"].(string)
	if schedID == "" {
		t.Fatal("step2: response missing schedule id")
	}
	t.Logf("step2: schedule created id=%s", schedID)

	// ── Step 3: List schedules — must contain the new schedule ───────────────
	rr = do(t, h, http.MethodGet, "/api/schedules", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("step3 GET /api/schedules: status=%d", rr.Code)
	}
	body3 := rr.Body.String()
	if !strings.Contains(body3, schedID) {
		t.Errorf("step3: schedule %s not found in list: %s", schedID, body3)
	}

	// ── Step 4: Delete the schedule ──────────────────────────────────────────
	rr = do(t, h, http.MethodDelete, "/api/schedules/"+schedID, nil)
	if rr.Code != http.StatusOK && rr.Code != http.StatusNoContent {
		t.Fatalf("step4 DELETE /api/schedules/%s: status=%d", schedID, rr.Code)
	}

	// Confirm deletion — id must no longer appear
	rr = do(t, h, http.MethodGet, "/api/schedules", nil)
	if strings.Contains(rr.Body.String(), schedID) {
		t.Errorf("step4: schedule %s still present after delete", schedID)
	}
	t.Logf("step4: schedule deleted and confirmed gone")

	// ── Step 5: Mutate a payload (LLM offline → rule-based fallback) ─────────
	rr = do(t, h, http.MethodPost, "/api/mutate", map[string]string{
		"payload":    "' OR 1=1-- -",
		"vuln_type":  "sqli",
		"tech_stack": "mysql",
		"waf":        "none",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("step5 POST /api/mutate: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var mutResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&mutResp)
	variants, ok := mutResp["variants"]
	if !ok {
		t.Fatal("step5: response missing 'variants'")
	}
	varList, _ := variants.([]interface{})
	if len(varList) == 0 {
		t.Error("step5: expected at least one payload variant")
	}
	t.Logf("step5: got %d payload variants", len(varList))

	// ── Step 6: Remediation list is a non-error JSON array ───────────────────
	rr = do(t, h, http.MethodGet, "/api/findings/remediation", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("step6 GET /api/findings/remediation: status=%d", rr.Code)
	}
	var remeds []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&remeds); err != nil {
		t.Errorf("step6: body is not a JSON array: %v", err)
	}

	// ── Step 7: Audit log is a non-error JSON array ───────────────────────────
	rr = do(t, h, http.MethodGet, "/api/audit", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("step7 GET /api/audit: status=%d", rr.Code)
	}
	var events []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&events); err != nil {
		t.Errorf("step7: body is not a JSON array: %v", err)
	}

	// ── Step 8: Final health check ───────────────────────────────────────────
	rr = do(t, h, http.MethodGet, "/api/health", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("step8 GET /api/health: status=%d", rr.Code)
	}
	t.Log("step8: health OK — full journey complete")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
