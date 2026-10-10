package execution

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestFirewallControllerAtomicRulesAndRevocation(t *testing.T) {
	fc := NewFirewallController()

	appliedPayloads := []string{}
	fc.SetCommandRunner(func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		if name == "iptables-restore" {
			appliedPayloads = append(appliedPayloads, string(stdin))
		}
		return []byte("ok"), nil
	})

	auth := policy.Authorization{
		FlowID:           "flow-1",
		AllowedProtocols: []string{"tcp", "udp"},
		Targets: []policy.Target{
			{Host: "1.1.1.1", Port: 80},
		},
	}

	rules := BuildRulesFromAuth(auth)
	if err := fc.ApplyFlowRules(context.Background(), "flow-1", rules); err != nil {
		t.Fatalf("ApplyFlowRules failed: %v", err)
	}

	if !fc.IsAllowed("flow-1", net.ParseIP("1.1.1.1"), 80, "tcp") {
		t.Fatal("1.1.1.1:80 TCP should be allowed")
	}

	if !fc.IsAllowed("flow-1", net.ParseIP("1.1.1.1"), 80, "udp") {
		t.Fatal("1.1.1.1:80 UDP should be allowed")
	}

	if fc.IsAllowed("flow-1", net.ParseIP("1.1.1.1"), 443, "tcp") {
		t.Fatal("1.1.1.1:443 TCP should NOT be allowed")
	}

	if fc.IsAllowed("flow-1", net.ParseIP("8.8.8.8"), 80, "tcp") {
		t.Fatal("8.8.8.8:80 TCP should NOT be allowed")
	}

	if len(appliedPayloads) == 0 {
		t.Fatal("no iptables-restore payload applied")
	}

	if !strings.Contains(appliedPayloads[0], "-F MIRAGE-EGRESS") {
		t.Fatalf("Payload missing chain flush: %s", appliedPayloads[0])
	}

	if err := fc.RevokeFlowRules(context.Background(), "flow-1"); err != nil {
		t.Fatalf("RevokeFlowRules failed: %v", err)
	}

	if fc.IsAllowed("flow-1", net.ParseIP("1.1.1.1"), 80, "tcp") {
		t.Fatal("revoked flow should be blocked")
	}
}
