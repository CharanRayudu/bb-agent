package notify_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/notify"
)

func TestStore_CreateAndList(t *testing.T) {
	st := notify.NewStore()

	ch, err := st.Create("slack-ops", notify.ChannelSlack, notify.ChannelConfig{
		WebhookURL: "https://hooks.slack.com/test",
	}, []string{"critical_finding", "scan_complete"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ch.ID == "" {
		t.Error("expected non-empty ID")
	}
	if ch.Type != notify.ChannelSlack {
		t.Errorf("type = %q, want slack", ch.Type)
	}
	if !ch.Enabled {
		t.Error("expected enabled=true by default")
	}

	list := st.List()
	if len(list) != 1 {
		t.Fatalf("List: got %d, want 1", len(list))
	}
	if list[0].ID != ch.ID {
		t.Errorf("list[0].ID = %q, want %q", list[0].ID, ch.ID)
	}
}

func TestStore_Create_ValidationErrors(t *testing.T) {
	st := notify.NewStore()

	_, err := st.Create("", notify.ChannelSlack, notify.ChannelConfig{}, nil)
	if err == nil {
		t.Error("expected error for empty name")
	}

	_, err = st.Create("x", "badtype", notify.ChannelConfig{}, nil)
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestStore_Get(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("wh", notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: "https://x.y"}, nil)

	got, ok := st.Get(ch.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Name != "wh" {
		t.Errorf("Name = %q, want wh", got.Name)
	}

	_, ok = st.Get("nonexistent")
	if ok {
		t.Error("Get nonexistent: expected not found")
	}
}

func TestStore_Update(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("orig", notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: "https://a.b"}, []string{"scan_complete"})

	err := st.Update(ch.ID, "updated", notify.ChannelConfig{WebhookURL: "https://c.d"}, []string{"high_finding"}, false)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := st.Get(ch.ID)
	if got.Name != "updated" {
		t.Errorf("Name = %q, want updated", got.Name)
	}
	if got.Enabled {
		t.Error("expected enabled=false after update")
	}
	if len(got.Events) != 1 || got.Events[0] != "high_finding" {
		t.Errorf("Events = %v, want [high_finding]", got.Events)
	}
}

func TestStore_Update_NotFound(t *testing.T) {
	st := notify.NewStore()
	err := st.Update("ghost", "x", notify.ChannelConfig{}, nil, true)
	if err == nil {
		t.Error("expected error for nonexistent id")
	}
}

func TestStore_Delete(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("del", notify.ChannelEmail, notify.ChannelConfig{}, nil)

	if err := st.Delete(ch.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := st.Get(ch.ID); ok {
		t.Error("channel still exists after Delete")
	}

	if err := st.Delete(ch.ID); err == nil {
		t.Error("expected error deleting nonexistent channel")
	}
}

func TestStore_ForEvent(t *testing.T) {
	st := notify.NewStore()
	c1, _ := st.Create("c1", notify.ChannelSlack, notify.ChannelConfig{WebhookURL: "https://x"}, []string{"critical_finding", "scan_complete"})
	c2, _ := st.Create("c2", notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: "https://y"}, []string{"high_finding"})

	// Disable c1 after creation
	st.Update(c1.ID, "c1", notify.ChannelConfig{WebhookURL: "https://x"}, []string{"critical_finding"}, false)

	// c1 disabled → should not be returned
	res := st.ForEvent("critical_finding")
	for _, ch := range res {
		if ch.ID == c1.ID {
			t.Error("disabled channel returned by ForEvent")
		}
	}

	// c2 subscribes to high_finding
	res = st.ForEvent("high_finding")
	if len(res) != 1 || res[0].ID != c2.ID {
		t.Errorf("ForEvent(high_finding): got %d channels, want 1 with id %s", len(res), c2.ID)
	}

	// No channel for unsubscribed event
	res = st.ForEvent("monitor_alert")
	if len(res) != 0 {
		t.Errorf("ForEvent(monitor_alert): expected 0, got %d", len(res))
	}
}

func TestStore_MarkTested(t *testing.T) {
	st := notify.NewStore()
	ch, _ := st.Create("t", notify.ChannelSlack, notify.ChannelConfig{WebhookURL: "https://x"}, nil)

	if _, ok := st.Get(ch.ID); !ok {
		t.Fatal("not found")
	}
	st.MarkTested(ch.ID)
	got, _ := st.Get(ch.ID)
	if got.TestedAt == nil {
		t.Error("TestedAt should be set after MarkTested")
	}
}

func TestStore_SupportedEvents(t *testing.T) {
	expected := []string{"critical_finding", "high_finding", "scan_complete", "sla_breach", "schedule_fired", "monitor_alert"}
	if len(notify.SupportedEvents) != len(expected) {
		t.Errorf("SupportedEvents length = %d, want %d", len(notify.SupportedEvents), len(expected))
	}
	set := make(map[string]bool)
	for _, e := range notify.SupportedEvents {
		set[e] = true
	}
	for _, e := range expected {
		if !set[e] {
			t.Errorf("SupportedEvents missing %q", e)
		}
	}
}

func TestStore_ListSortedByCreatedAt(t *testing.T) {
	st := notify.NewStore()
	for _, name := range []string{"a", "b", "c"} {
		st.Create(name, notify.ChannelWebhook, notify.ChannelConfig{WebhookURL: "https://x"}, nil) //nolint
	}
	list := st.List()
	if len(list) != 3 {
		t.Fatalf("want 3 channels, got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.Before(list[i-1].CreatedAt) {
			t.Errorf("list not sorted by CreatedAt: %s before %s", list[i].CreatedAt, list[i-1].CreatedAt)
		}
	}
}
