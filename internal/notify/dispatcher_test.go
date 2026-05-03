package notify_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/notify"
)

// fakeServer starts an httptest.Server that records received requests.
func fakeServer(t *testing.T) (*httptest.Server, *[][]byte) {
	t.Helper()
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf []byte
		if r.Body != nil {
			buf = make([]byte, r.ContentLength)
			r.Body.Read(buf) //nolint
		}
		bodies = append(bodies, buf)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func TestDispatcher_Dispatch_WebhookDelivery(t *testing.T) {
	srv, bodies := fakeServer(t)

	st := notify.NewStore()
	ch, err := st.Create("webhook-ch", notify.ChannelWebhook, notify.ChannelConfig{
		WebhookURL: srv.URL,
	}, []string{"scan_complete"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = ch

	d := notify.NewDispatcher(st)
	d.Dispatch("scan_complete", map[string]interface{}{"target": "https://example.com"})

	// Wait for async goroutine
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(*bodies) == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	if len(*bodies) == 0 {
		t.Fatal("expected webhook body, got none")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal((*bodies)[0], &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["event"] != "scan_complete" {
		t.Errorf("event = %v, want scan_complete", payload["event"])
	}
}

func TestDispatcher_Dispatch_NoChannels(t *testing.T) {
	st := notify.NewStore()
	d := notify.NewDispatcher(st)
	// Should not panic with zero channels
	d.Dispatch("scan_complete", map[string]interface{}{})
}

func TestDispatcher_Dispatch_SkipsDisabledChannels(t *testing.T) {
	srv, bodies := fakeServer(t)

	st := notify.NewStore()
	ch, _ := st.Create("disabled-ch", notify.ChannelWebhook, notify.ChannelConfig{
		WebhookURL: srv.URL,
	}, []string{"critical_finding"})
	st.Update(ch.ID, "disabled-ch", notify.ChannelConfig{WebhookURL: srv.URL}, []string{"critical_finding"}, false)

	d := notify.NewDispatcher(st)
	d.Dispatch("critical_finding", map[string]interface{}{})

	time.Sleep(100 * time.Millisecond)
	if len(*bodies) != 0 {
		t.Errorf("expected 0 deliveries to disabled channel, got %d", len(*bodies))
	}
}

func TestDispatcher_Dispatch_SlackFormat(t *testing.T) {
	srv, bodies := fakeServer(t)

	st := notify.NewStore()
	st.Create("slack-ch", notify.ChannelSlack, notify.ChannelConfig{
		WebhookURL: srv.URL,
	}, []string{"critical_finding"})

	d := notify.NewDispatcher(st)
	d.Dispatch("critical_finding", map[string]interface{}{"title": "SQLi detected", "target": "https://api.example.com"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(*bodies) == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	if len(*bodies) == 0 {
		t.Fatal("expected slack payload, got none")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal((*bodies)[0], &payload); err != nil {
		t.Fatalf("unmarshal slack payload: %v", err)
	}
	// Slack format should have a "text" field (not "event")
	if _, ok := payload["text"]; !ok {
		t.Error("slack payload missing 'text' field")
	}
}

func TestDispatcher_Test_ChannelNotFound(t *testing.T) {
	st := notify.NewStore()
	d := notify.NewDispatcher(st)
	if err := d.Test("nonexistent"); err == nil {
		t.Error("expected error for nonexistent channel")
	}
}

func TestDispatcher_Test_WebhookSendsTestPayload(t *testing.T) {
	srv, bodies := fakeServer(t)

	st := notify.NewStore()
	ch, _ := st.Create("test-ch", notify.ChannelWebhook, notify.ChannelConfig{
		WebhookURL: srv.URL,
	}, nil)

	d := notify.NewDispatcher(st)
	if err := d.Test(ch.ID); err != nil {
		t.Fatalf("Test: %v", err)
	}

	if len(*bodies) == 0 {
		t.Fatal("expected test payload delivery, got none")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal((*bodies)[0], &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["event"] != "test" {
		t.Errorf("test payload event = %v, want test", payload["event"])
	}
	// MarkTested should have been called
	got, _ := st.Get(ch.ID)
	if got.TestedAt == nil {
		t.Error("TestedAt should be set after successful Test()")
	}
}

func TestDispatcher_Test_EmailMissingConfig(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("email-ch", notify.ChannelEmail, notify.ChannelConfig{
		// No smtp_host or to — should fail
	}, nil)

	d := notify.NewDispatcher(st)
	err := d.Test(ch.ID)
	if err == nil {
		t.Error("expected error for email channel with missing config")
	}
}

func TestDispatcher_Test_WebhookBadURL(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("bad-wh", notify.ChannelWebhook, notify.ChannelConfig{
		WebhookURL: "", // empty
	}, nil)

	d := notify.NewDispatcher(st)
	err := d.Test(ch.ID)
	if err == nil {
		t.Error("expected error for webhook with empty URL")
	}
}

func TestDispatcher_Dispatch_MultipleChannels(t *testing.T) {
	srv1, bodies1 := fakeServer(t)
	srv2, bodies2 := fakeServer(t)

	st := notify.NewStore()
	st.Create("ch1", notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: srv1.URL}, []string{"high_finding"})
	st.Create("ch2", notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: srv2.URL}, []string{"high_finding"})

	d := notify.NewDispatcher(st)
	d.Dispatch("high_finding", map[string]interface{}{"severity": "high"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (len(*bodies1) == 0 || len(*bodies2) == 0) {
		time.Sleep(20 * time.Millisecond)
	}

	if len(*bodies1) == 0 {
		t.Error("ch1 did not receive delivery")
	}
	if len(*bodies2) == 0 {
		t.Error("ch2 did not receive delivery")
	}
}
