package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Monitoring ─────────────────────────────────────────────────────────────────

func TestMonitors_ListEmpty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/monitors", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/monitors: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["monitors"]; !ok {
		t.Error("response missing 'monitors'")
	}
	count, _ := body["count"].(float64)
	if count != 0 {
		t.Errorf("count = %.0f, want 0", count)
	}
}

func TestMonitors_Create(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/monitors", map[string]interface{}{
		"name":          "Production Monitor",
		"target":        "https://api.example.com",
		"profile":       "quick-recon",
		"cron_expr":     "0 6 * * *",
		"alert_channels": []string{},
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/monitors: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["id"] == nil || m["id"] == "" {
		t.Error("expected non-empty monitor ID")
	}
	if m["target"] != "https://api.example.com" {
		t.Errorf("target = %v, want https://api.example.com", m["target"])
	}
}

func TestMonitors_Create_EmptyTarget(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/monitors", map[string]interface{}{
		"name":   "bad monitor",
		"target": "",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty target, got %d", rr.Code)
	}
}

func TestMonitors_Get(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/monitors", map[string]interface{}{
		"target": "https://example.com",
		"name":   "test",
	})
	var m map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&m) //nolint
	id := m["id"].(string)

	rr = do(t, h, http.MethodGet, "/api/monitors/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/monitors/%s: status=%d", id, rr.Code)
	}
}

func TestMonitors_Get_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/monitors/ghost-monitor", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent monitor, got %d", rr.Code)
	}
}

func TestMonitors_Delete(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/monitors", map[string]interface{}{
		"target": "https://target.example.com",
		"name":   "del-monitor",
	})
	var m map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&m) //nolint
	id := m["id"].(string)

	rr = do(t, h, http.MethodDelete, "/api/monitors/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE /api/monitors/%s: status=%d body=%s", id, rr.Code, rr.Body.String())
	}

	// Verify gone
	rr = do(t, h, http.MethodGet, "/api/monitors/"+id, nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", rr.Code)
	}
}

// TestMonitors_Baseline and TestMonitors_Deltas require a live DB (queries.GetAllFindings).
// They are covered by the e2e tests; skipped here since newTestHandler uses nil DB.

func TestMonitors_Deltas_NoBaseline(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/monitors", map[string]interface{}{
		"target": "https://deltas.example.com",
		"name":   "delta-test",
	})
	var m map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&m) //nolint
	id := m["id"].(string)

	// /deltas returns an empty list when no baseline has been set — no DB needed
	rr = do(t, h, http.MethodGet, "/api/monitors/"+id+"/deltas", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /deltas (no baseline): status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitors_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/monitors", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE on collection, got %d", rr.Code)
	}
}

// ── Alert Channels ─────────────────────────────────────────────────────────────

func TestAlertChannels_List(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/alerting/channels", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/alerting/channels: status=%d", rr.Code)
	}
}
