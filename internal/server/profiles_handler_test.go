package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Scan Profiles ─────────────────────────────────────────────────────────────

func TestProfiles_List(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/profiles", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	profiles, _ := body["profiles"].([]interface{})
	if len(profiles) == 0 {
		t.Error("expected built-in profiles, got none")
	}
	count, _ := body["count"].(float64)
	if int(count) != len(profiles) {
		t.Errorf("count=%d != len(profiles)=%d", int(count), len(profiles))
	}
}

func TestProfiles_List_CategoryFilter(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/profiles?category=web", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles?category=web: status=%d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body) //nolint
	profiles, _ := body["profiles"].([]interface{})
	for _, p := range profiles {
		pm := p.(map[string]interface{})
		if pm["category"] != "web" {
			t.Errorf("profile %v has category %v, want web", pm["id"], pm["category"])
		}
	}
}

func TestProfiles_GetBuiltin(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/profiles/quick-recon", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles/quick-recon: status=%d", rr.Code)
	}
	var p map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&p) //nolint
	if p["id"] != "quick-recon" {
		t.Errorf("id = %v, want quick-recon", p["id"])
	}
	if p["builtin"] != true {
		t.Errorf("builtin = %v, want true", p["builtin"])
	}
}

func TestProfiles_Get_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/profiles/ghost-id", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent profile, got %d", rr.Code)
	}
}

func TestProfiles_Create(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/profiles", map[string]interface{}{
		"name":        "My Custom Profile",
		"description": "Custom scan for internal apps",
		"category":    "custom",
		"color":       "#ff0000",
		"agents":      []map[string]interface{}{{"id": "xss_scanner", "enabled": true}},
		"tags":        []string{"internal", "custom"},
	})
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/profiles: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&p) //nolint
	if p["id"] == nil || p["id"] == "" {
		t.Error("expected non-empty ID")
	}
	if p["builtin"] == true {
		t.Error("custom profile should not be builtin")
	}
}

func TestProfiles_Create_EmptyName(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/profiles", map[string]interface{}{
		"name": "",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty name, got %d", rr.Code)
	}
}

func TestProfiles_Clone(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/profiles/owasp-top10/clone", nil)
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST clone: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&p) //nolint
	if p["id"] == "owasp-top10" {
		t.Error("clone should have a different ID")
	}
	if p["builtin"] == true {
		t.Error("clone should not be builtin")
	}
}

func TestProfiles_Clone_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/profiles/ghost-id/clone", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for clone of nonexistent profile, got %d", rr.Code)
	}
}

func TestProfiles_Update_Builtin_Rejected(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPut, "/api/profiles/quick-recon", map[string]interface{}{
		"name": "hacked",
	})
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("expected 400/403 for updating builtin, got %d", rr.Code)
	}
}

func TestProfiles_Delete_Builtin_Rejected(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/profiles/owasp-top10", nil)
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Errorf("expected 400/403 for deleting builtin, got %d", rr.Code)
	}
}

func TestProfiles_Use_IncrementsCount(t *testing.T) {
	h := newTestHandler(t)
	// GET profile before use
	rr := do(t, h, http.MethodGet, "/api/profiles/quick-recon", nil)
	var before map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&before) //nolint
	countBefore, _ := before["use_count"].(float64)

	// Use profile
	do(t, h, http.MethodPost, "/api/profiles/quick-recon/use", nil) //nolint

	// GET profile after use
	rr = do(t, h, http.MethodGet, "/api/profiles/quick-recon", nil)
	var after map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&after) //nolint
	countAfter, _ := after["use_count"].(float64)

	if countAfter != countBefore+1 {
		t.Errorf("use_count: before=%.0f after=%.0f, expected increment by 1", countBefore, countAfter)
	}
}

func TestProfiles_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/profiles", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE on collection, got %d", rr.Code)
	}
}
