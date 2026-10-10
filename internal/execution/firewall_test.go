package execution

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestHostFirewallSeparatesTCPAndUDP(t *testing.T) {
	fc := NewFirewallController("")
	var payloads []string
	fc.SetCommandRunner(func(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		if name == "iptables-restore" {
			payloads = append(payloads, string(stdin))
		}
		return []byte("ok"), nil
	})
	fc.BindContainerIP("flow-1", net.ParseIP("172.18.0.4"))
	err := fc.ApplyFlowRules(context.Background(), "flow-1", []NetworkRule{{
		FlowID:   "flow-1",
		Protocol: "tcp",
		IP:       net.ParseIP("203.0.113.10"),
		Port:     443,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payloads=%d", len(payloads))
	}
	body := payloads[0]
	if !strings.Contains(body, "-s 172.18.0.4 -d 203.0.113.10 -p tcp --dport 443") {
		t.Fatalf("tcp rule missing:\n%s", body)
	}
	if strings.Contains(body, "-p udp") || strings.Contains(body, "-p all") {
		t.Fatalf("udp or all-protocol rule was emitted:\n%s", body)
	}
	if !strings.Contains(body, "-s 172.18.0.4") || !strings.Contains(body, "-j DROP") || !strings.Contains(body, "-j RETURN") {
		t.Fatalf("source drop or return missing:\n%s", body)
	}
	if fc.IsAllowed("flow-1", net.ParseIP("203.0.113.10"), 443, "tcp") {
		// expected
	} else {
		t.Fatal("tcp permit was not recorded")
	}
	if fc.IsAllowed("flow-1", net.ParseIP("203.0.113.10"), 443, "udp") {
		t.Fatal("tcp permit authorized udp")
	}
	if fc.IsAllowed("flow-1", net.ParseIP("198.51.100.8"), 443, "tcp") {
		t.Fatal("unlisted destination was allowed")
	}
}

func TestHostFirewallRejectsRulesWithoutADestination(t *testing.T) {
	fc := NewFirewallController("")
	fc.SetCommandRunner(func(context.Context, string, []string, []byte) ([]byte, error) {
		return nil, nil
	})
	fc.BindContainerIP("flow-1", net.ParseIP("172.18.0.4"))
	err := fc.ApplyFlowRules(context.Background(), "flow-1", []NetworkRule{{
		Protocol: "tcp",
		Port:     80,
	}})
	if err == nil {
		t.Fatal("rule without a destination was accepted")
	}
}

func TestRequestBudgetIsSharedAndConcurrent(t *testing.T) {
	book := policy.NewBook()
	auth := policy.Authorization{
		ID:           "auth-fuzz",
		FlowID:       "flow-fuzz",
		EngagementID: "eng-fuzz",
		Autonomy:     policy.AutonomyL3,
		MaxRequests:  50,
		Targets:      []policy.Target{{Host: "93.184.216.34", Port: 80, Scheme: "http"}},
	}
	book.Put(auth)
	child := auth.CloneForFlow("flow-fuzz-2")
	book.Put(child)

	var wg sync.WaitGroup
	okCount := 0
	var mu sync.Mutex
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			flow := "flow-fuzz"
			if n%2 == 0 {
				flow = "flow-fuzz-2"
			}
			if book.TryConsume(flow) {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if okCount != 50 {
		t.Fatalf("consumed=%d", okCount)
	}
}
