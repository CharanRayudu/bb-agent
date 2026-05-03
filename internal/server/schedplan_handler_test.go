package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Schedule Plans ─────────────────────────────────────────────────────────────

func TestSchedulePlans_List_Empty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/schedule-plans", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/schedule-plans: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["schedules"]; !ok {
		t.Error("response missing 'schedules' key")
	}
	if _, ok := body["presets"]; !ok {
		t.Error("response missing 'presets' key")
	}
}

func TestSchedulePlans_CreateAndGet(t *testing.T) {
	h := newTestHandler(t)

	// Create
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"name":         "Nightly Scan",
		"target":       "https://target.example.com",
		"profile_id":   "owasp-top10",
		"profile_name": "OWASP Top 10",
		"cron":         "@daily",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/schedule-plans: status=%d body=%s", rr.Code, rr.Body.String())
	}

	var sc map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&sc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id, _ := sc["id"].(string)
	if id == "" {
		t.Fatal("expected non-empty schedule ID")
	}

	// Get by ID
	rr = do(t, h, http.MethodGet, "/api/schedule-plans/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/schedule-plans/%s: status=%d", id, rr.Code)
	}
}

func TestSchedulePlans_Create_InvalidCron(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"name":   "bad",
		"target": "https://x.com",
		"cron":   "@invalid",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid cron, got %d", rr.Code)
	}
}

func TestSchedulePlans_Create_MissingFields(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"cron": "@daily",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name/target, got %d", rr.Code)
	}
}

func TestSchedulePlans_Toggle(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"name": "s", "target": "https://x.com", "cron": "@weekly",
	})
	var sc map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	id := sc["id"].(string)

	// Toggle off
	rr = do(t, h, http.MethodPost, "/api/schedule-plans/"+id+"/toggle", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST toggle: status=%d", rr.Code)
	}
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	if sc["enabled"].(bool) {
		t.Error("expected enabled=false after toggle")
	}

	// Toggle on
	rr = do(t, h, http.MethodPost, "/api/schedule-plans/"+id+"/toggle", nil)
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	if !sc["enabled"].(bool) {
		t.Error("expected enabled=true after second toggle")
	}
}

func TestSchedulePlans_Toggle_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans/ghost/toggle", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent schedule toggle, got %d", rr.Code)
	}
}

func TestSchedulePlans_Update(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"name": "orig", "target": "https://old.com", "cron": "@hourly",
	})
	var sc map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	id := sc["id"].(string)

	rr = do(t, h, http.MethodPut, "/api/schedule-plans/"+id, map[string]string{
		"name": "updated", "target": "https://new.com", "cron": "@daily",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /api/schedule-plans/%s: status=%d body=%s", id, rr.Code, rr.Body.String())
	}
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	if sc["name"] != "updated" {
		t.Errorf("name = %v, want updated", sc["name"])
	}
}

func TestSchedulePlans_Delete(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans", map[string]string{
		"name": "del", "target": "https://x.com", "cron": "@monthly",
	})
	var sc map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&sc) //nolint
	id := sc["id"].(string)

	rr = do(t, h, http.MethodDelete, "/api/schedule-plans/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE: status=%d", rr.Code)
	}

	// Verify gone
	rr = do(t, h, http.MethodGet, "/api/schedule-plans/"+id, nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", rr.Code)
	}
}

func TestSchedulePlans_Run_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/schedule-plans/ghost/run", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent run, got %d", rr.Code)
	}
}

func TestSchedulePlans_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/schedule-plans", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE on collection, got %d", rr.Code)
	}
}
