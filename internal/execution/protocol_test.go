package execution

import (
	"context"
	"net"
	"testing"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestTCPAndUDPSeparationInPermissions(t *testing.T) {
	engine := policy.Engine{}

	tcpAuth := &policy.Authorization{
		FlowID:           "flow-tcp",
		Autonomy:         policy.AutonomyL3,
		AllowedProtocols: []string{"tcp", "http", "https"},
		Targets: []policy.Target{
			{Host: "53.53.53.53", Port: 53},
		},
	}

	tcpSubject := policy.Subject{
		Scheme: "tcp",
		Risk:   policy.RiskPassive,
		Host:   "53.53.53.53",
		Port:   53,
		IPs:    []string{"53.53.53.53"},
	}

	udpSubject := policy.Subject{
		Scheme: "udp",
		Risk:   policy.RiskPassive,
		Host:   "53.53.53.53",
		Port:   53,
		IPs:    []string{"53.53.53.53"},
	}

	decTCP := engine.Decide(tcpAuth, tcpSubject, nil, policy.NewBook().Put(*tcpAuth).NotBefore)
	if !decTCP.Allowed {
		t.Fatalf("TCP action should be allowed, reason: %s", decTCP.Reason)
	}

	decUDP := engine.Decide(tcpAuth, udpSubject, nil, policy.NewBook().Put(*tcpAuth).NotBefore)
	if decUDP.Allowed {
		t.Fatal("UDP action should be denied when AllowedProtocols only includes tcp/http/https")
	}

	udpAuth := &policy.Authorization{
		FlowID:           "flow-udp",
		Autonomy:         policy.AutonomyL3,
		AllowedProtocols: []string{"udp"},
		Targets: []policy.Target{
			{Host: "53.53.53.53", Port: 53},
		},
	}

	decUDP2 := engine.Decide(udpAuth, udpSubject, nil, policy.NewBook().Put(*udpAuth).NotBefore)
	if !decUDP2.Allowed {
		t.Fatalf("UDP action should be allowed when AllowedProtocols includes udp, reason: %s", decUDP2.Reason)
	}

	// Test real UDP connection dialer check
	fc := NewFirewallController()
	fc.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	})
	_ = fc.ApplyFlowRules(context.Background(), "flow-udp", BuildRulesFromAuth(*udpAuth))

	if !fc.IsAllowed("flow-udp", net.ParseIP("53.53.53.53"), 53, "udp") {
		t.Fatal("FirewallController should allow UDP 53.53.53.53:53")
	}
	if fc.IsAllowed("flow-udp", net.ParseIP("53.53.53.53"), 53, "tcp") {
		t.Fatal("FirewallController should block TCP when only UDP is allowed")
	}
}
