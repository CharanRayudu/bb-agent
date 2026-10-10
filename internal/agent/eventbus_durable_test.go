package agent

import (
	"testing"
	"time"
)

func TestResetKeepsDurableSubscribers(t *testing.T) {
	bus := NewEventBus()
	got := make(chan string, 2)
	bus.SubscribeDurable("queue_metrics", func(data interface{}) {
		got <- "durable"
	})
	bus.Subscribe(EventLeadDiscovered, func(data interface{}) {
		got <- "local"
	})
	bus.Reset()
	bus.Emit("queue_metrics", map[string]interface{}{"ok": true})
	bus.Emit(EventLeadDiscovered, "gone")
	select {
	case value := <-got:
		if value != "durable" {
			t.Fatalf("first event=%s", value)
		}
	case <-time.After(time.Second):
		t.Fatal("durable queue_metrics listener was removed when the scan reset the bus")
	}
	select {
	case value := <-got:
		t.Fatalf("scan-local subscriber survived reset: %s", value)
	case <-time.After(200 * time.Millisecond):
	}
}
