package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Posture Handler ────────────────────────────────────────────────────────────

func TestPosture_Get(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/posture", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/posture: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["score"]; !ok {
		t.Error("response missing 'score'")
	}
	if _, ok := body["grade"]; !ok {
		t.Error("response missing 'grade'")
	}
	if _, ok := body["components"]; !ok {
		t.Error("response missing 'components'")
	}
	if _, ok := body["owasp_coverage"]; !ok {
		t.Error("response missing 'owasp_coverage'")
	}
	if _, ok := body["urgent_actions"]; !ok {
		t.Error("response missing 'urgent_actions'")
	}

	score, _ := body["score"].(float64)
	if score < 0 || score > 100 {
		t.Errorf("score = %.1f, want [0,100]", score)
	}

	grade, _ := body["grade"].(string)
	valid := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !valid[grade] {
		t.Errorf("grade = %q, want A-F", grade)
	}
}

func TestPosture_History(t *testing.T) {
	h := newTestHandler(t)
	// Trigger a posture computation first to seed history
	do(t, h, http.MethodGet, "/api/posture", nil) //nolint

	rr := do(t, h, http.MethodGet, "/api/posture/history", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/posture/history: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["history"]; !ok {
		t.Error("response missing 'history'")
	}
}

func TestPosture_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/posture", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on posture, got %d", rr.Code)
	}
}

func TestPosture_History_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/posture/history", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on history, got %d", rr.Code)
	}
}
