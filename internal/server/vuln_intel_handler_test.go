package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Vulnerability Intelligence ─────────────────────────────────────────────────

func TestFindingStats_Empty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/stats", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/findings/stats: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["by_severity"]; !ok {
		t.Error("response missing 'by_severity'")
	}
	if _, ok := body["top_types"]; !ok {
		t.Error("response missing 'top_types'")
	}
	if _, ok := body["trend"]; !ok {
		t.Error("response missing 'trend'")
	}
}

func TestFindingStats_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/findings/stats", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on stats, got %d", rr.Code)
	}
}

func TestFindingSearch_Empty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/search", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/findings/search: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	findings, _ := body["findings"].([]interface{})
	if findings == nil {
		t.Error("response should have 'findings' array")
	}
	if _, ok := body["total"]; !ok {
		t.Error("response missing 'total'")
	}
	if _, ok := body["page"]; !ok {
		t.Error("response missing 'page'")
	}
}

func TestFindingSearch_PaginationDefaults(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/search?page=0&limit=0", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("search with page=0: status=%d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body) //nolint
	// page should default to 1, limit to 50
	page, _ := body["page"].(float64)
	limit, _ := body["limit"].(float64)
	if page != 1 {
		t.Errorf("default page = %.0f, want 1", page)
	}
	if limit != 50 {
		t.Errorf("default limit = %.0f, want 50", limit)
	}
}

func TestFindingSearch_LimitCap(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/search?limit=9999", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("search with large limit: status=%d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body) //nolint
	limit, _ := body["limit"].(float64)
	if limit > 200 {
		t.Errorf("limit should be capped at 200, got %.0f", limit)
	}
}

func TestFindingSearch_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/findings/search", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on search, got %d", rr.Code)
	}
}

func TestFindingExport_CSV(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/findings/export", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/findings/export: status=%d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct == "" || (ct != "text/csv; charset=utf-8" && ct != "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if cd == "" {
		t.Error("Content-Disposition should be set for CSV export")
	}
	// Body should at least have CSV header row
	body := rr.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty CSV body (at minimum header row)")
	}
}

func TestFindingExport_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/findings/export", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on export, got %d", rr.Code)
	}
}
