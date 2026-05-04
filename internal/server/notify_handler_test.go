package server_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ── Notification Channels ─────────────────────────────────────────────────────

func TestNotifyChannels_ListEmpty(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/notify/channels", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/notify/channels: status=%d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["channels"]; !ok {
		t.Error("response missing 'channels' key")
	}
	if _, ok := body["events"]; !ok {
		t.Error("response missing 'events' key")
	}
	count, _ := body["count"].(float64)
	if count != 0 {
		t.Errorf("count = %.0f, want 0", count)
	}
}

func TestNotifyChannels_CreateWebhook(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name":   "ops-webhook",
		"type":   "webhook",
		"config": map[string]interface{}{"webhook_url": "https://hooks.example.com/notify"},
		"events": []string{"critical_finding", "scan_complete"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/notify/channels: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var ch map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&ch); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ch["id"] == nil || ch["id"] == "" {
		t.Error("expected non-empty channel ID")
	}
	if ch["type"] != "webhook" {
		t.Errorf("type = %v, want webhook", ch["type"])
	}
	if ch["enabled"] != true {
		t.Errorf("enabled = %v, want true", ch["enabled"])
	}
}

func TestNotifyChannels_CreateSlack(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name":   "slack-ops",
		"type":   "slack",
		"config": map[string]interface{}{"webhook_url": "https://hooks.slack.com/services/test"},
		"events": []string{"critical_finding"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST slack: status=%d", rr.Code)
	}
}

func TestNotifyChannels_Create_InvalidType(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name": "bad",
		"type": "telegram",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid type, got %d", rr.Code)
	}
}

func TestNotifyChannels_Create_EmptyName(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name": "",
		"type": "webhook",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty name, got %d", rr.Code)
	}
}

func TestNotifyChannels_GetByID(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name": "ch", "type": "webhook",
		"config": map[string]interface{}{"webhook_url": "https://x.y"},
	})
	var ch map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&ch) //nolint
	id := ch["id"].(string)

	rr = do(t, h, http.MethodGet, "/api/notify/channels/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET channel: status=%d", rr.Code)
	}
}

func TestNotifyChannels_GetByID_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/notify/channels/ch_ghost123", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent channel, got %d", rr.Code)
	}
}

func TestNotifyChannels_Update(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name": "orig", "type": "webhook",
		"config": map[string]interface{}{"webhook_url": "https://a.b"},
		"events": []string{"scan_complete"},
	})
	var ch map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&ch) //nolint
	id := ch["id"].(string)

	rr = do(t, h, http.MethodPut, "/api/notify/channels/"+id, map[string]interface{}{
		"name":    "updated",
		"config":  map[string]interface{}{"webhook_url": "https://c.d"},
		"events":  []string{"high_finding"},
		"enabled": false,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT channel: status=%d body=%s", rr.Code, rr.Body.String())
	}
	json.NewDecoder(rr.Body).Decode(&ch) //nolint
	if ch["name"] != "updated" {
		t.Errorf("name = %v, want updated", ch["name"])
	}
	if ch["enabled"] != false {
		t.Errorf("enabled = %v, want false", ch["enabled"])
	}
}

func TestNotifyChannels_Delete(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels", map[string]interface{}{
		"name": "del", "type": "email",
	})
	var ch map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&ch) //nolint
	id := ch["id"].(string)

	rr = do(t, h, http.MethodDelete, "/api/notify/channels/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE channel: status=%d", rr.Code)
	}

	// Verify gone
	rr = do(t, h, http.MethodGet, "/api/notify/channels/"+id, nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", rr.Code)
	}
}

func TestNotifyChannels_Delete_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/notify/channels/ch_ghost999", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent delete, got %d", rr.Code)
	}
}

func TestNotifyChannels_Test_NotFound(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/channels/ch_ghost/test", nil)
	// Dispatcher.Test returns error → 502 or similar
	if rr.Code == http.StatusOK {
		t.Error("expected non-200 for test on nonexistent channel")
	}
}

func TestNotifyEvents_List(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodGet, "/api/notify/events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/notify/events: status=%d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body) //nolint
	events, _ := body["events"].([]interface{})
	if len(events) == 0 {
		t.Error("expected supported events list, got empty")
	}
}

func TestNotifyEvents_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodPost, "/api/notify/events", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on events, got %d", rr.Code)
	}
}

func TestNotifyChannels_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/notify/channels", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE on collection, got %d", rr.Code)
	}
}
