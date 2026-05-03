package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Remediation Tracking ───────────────────────────────────────────────────────

func TestRemediationItems_ListEmpty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/remediation/items", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/remediation/items: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["items"]; !ok {
		t.Error("response missing 'items'")
	}
}

func TestRemediationItems_Create(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/remediation/items", map[string]interface{}{
		"finding_id":   "finding-xyz",
		"title":        "SQL Injection in /api/search",
		"description":  "UNION-based SQLi confirmed",
		"severity":     "critical",
		"target":       "https://api.example.com",
		"finding_type": "SQLi",
		"flow_id":      "flow-123",
		"risk_score":   9.8,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/remediation/items: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var item map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&item); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if item["id"] == nil || item["id"] == "" {
		t.Error("expected non-empty ID")
	}
	if item["status"] != "open" {
		t.Errorf("status = %v, want open", item["status"])
	}
}

func TestRemediationItems_Create_MissingTitle(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/remediation/items", map[string]interface{}{
		"finding_id": "f1",
		"severity":   "high",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing title, got %d", rr.Code)
	}
}

func TestRemediationItems_ListFilter(t *testing.T) {
	h := newTestHandler(t)
	// Create one item
	rr := do(t, h, http.MethodPost, "/api/remediation/items", map[string]interface{}{
		"title": "XSS", "severity": "high", "finding_id": "f1",
	})
	var item map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&item) //nolint

	// List open items
	rr = do(t, h, http.MethodGet, "/api/remediation/items?status=open", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET ?status=open: status=%d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body) //nolint
	items, _ := body["items"].([]interface{})
	if len(items) == 0 {
		t.Error("expected at least 1 open item")
	}
}

func TestRemediationItems_StatusTransition(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/remediation/items", map[string]interface{}{
		"title": "Test Item", "severity": "medium", "finding_id": "f2",
	})
	var item map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&item) //nolint
	id := item["id"].(string)

	// Transition to in_progress
	rr = do(t, h, http.MethodPost, "/api/remediation/items/"+id+"/status", map[string]interface{}{
		"status":   "in_progress",
		"assignee": "security-team",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /status: status=%d body=%s", rr.Code, rr.Body.String())
	}
	json.NewDecoder(rr.Body).Decode(&item) //nolint
	if item["status"] != "in_progress" {
		t.Errorf("status = %v, want in_progress", item["status"])
	}
}

func TestRemediationItems_AddNote(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/remediation/items", map[string]interface{}{
		"title": "Note Test Item", "severity": "low", "finding_id": "f3",
	})
	var item map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&item) //nolint
	id := item["id"].(string)

	rr = do(t, h, http.MethodPost, "/api/remediation/items/"+id+"/notes", map[string]interface{}{
		"author":  "analyst",
		"content": "Confirmed exploitable in production environment.",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /notes: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var note map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&note) //nolint
	if note["id"] == nil {
		t.Error("expected note ID")
	}
}

func TestRemediationMetrics(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/remediation/metrics", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/remediation/metrics: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["total"]; !ok {
		t.Error("response missing 'total'")
	}
	if _, ok := body["by_status"]; !ok {
		t.Error("response missing 'by_status'")
	}
	if _, ok := body["sla_breached"]; !ok {
		t.Error("response missing 'sla_breached'")
	}
}

func TestRemediationItems_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/remediation/items", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE on collection, got %d", rr.Code)
	}
}
