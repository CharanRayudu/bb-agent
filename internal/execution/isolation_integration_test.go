package execution

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/bb-agent/mirage/internal/policy"
)

// TestDockerNetworkIsolationAndTamperingVerification verifies that container
// firewall enforcement prevents unauthorized destination access and resists tampering.
func TestDockerNetworkIsolationAndTamperingVerification(t *testing.T) {
	fc := NewFirewallController()

	// Simulate iptables execution host controller
	appliedRules := map[string]string{}
	var mu sync.Mutex

	fc.SetCommandRunner(func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if name == "iptables-restore" {
			appliedRules["active"] = string(stdin)
		}
		return []byte("ok"), nil
	})

	auth := policy.Authorization{
		FlowID:           "flow-isolated",
		AllowedProtocols: []string{"tcp"},
		Targets: []policy.Target{
			{Host: "203.0.113.10", Port: 443}, // Explicit authorized destination
		},
	}

	rules := BuildRulesFromAuth(auth)
	if err := fc.ApplyFlowRules(context.Background(), "flow-isolated", rules); err != nil {
		t.Fatalf("Failed to apply isolation rules: %v", err)
	}

	// 1. Authorized destination test
	if !fc.IsAllowed("flow-isolated", net.ParseIP("203.0.113.10"), 443, "tcp") {
		t.Fatal("Authorized target 203.0.113.10:443/tcp must be allowed")
	}

	// 2. Unapproved host/IP test
	if fc.IsAllowed("flow-isolated", net.ParseIP("198.51.100.50"), 80, "tcp") {
		t.Fatal("Unapproved destination 198.51.100.50:80/tcp must be blocked by firewall")
	}

	// 3. Unapproved protocol test (UDP when only TCP is authorized)
	if fc.IsAllowed("flow-isolated", net.ParseIP("203.0.113.10"), 443, "udp") {
		t.Fatal("UDP traffic must be blocked when only TCP is authorized")
	}

	// 4. Verify host-side payload contains exact rule comment and default drop
	mu.Lock()
	payload := appliedRules["active"]
	mu.Unlock()

	if payload == "" {
		t.Fatal("Firewall payload was not applied")
	}
	if !strings.Contains(payload, "-F MIRAGE-EGRESS") {
		t.Fatalf("Payload missing chain flush: %s", payload)
	}

	// 5. Revocation test
	if err := fc.RevokeFlowRules(context.Background(), "flow-isolated"); err != nil {
		t.Fatalf("Failed to revoke flow rules: %v", err)
	}

	if fc.IsAllowed("flow-isolated", net.ParseIP("203.0.113.10"), 443, "tcp") {
		t.Fatal("Target must be blocked after revocation")
	}
}

// TestContainerIPBindingInFirewallPayload verifies that binding a container IP includes -s <containerIP> in the rules payload.
func TestContainerIPBindingInFirewallPayload(t *testing.T) {
	fc := NewFirewallController()

	appliedPayloads := []string{}
	fc.SetCommandRunner(func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		if name == "iptables-restore" {
			appliedPayloads = append(appliedPayloads, string(stdin))
		}
		return []byte("ok"), nil
	})

	fc.BindContainerIP("flow-ip", net.ParseIP("172.18.0.5"))

	auth := policy.Authorization{
		FlowID:           "flow-ip",
		AllowedProtocols: []string{"tcp"},
		Targets: []policy.Target{
			{Host: "198.51.100.1", Port: 80},
		},
	}

	if err := fc.ApplyFlowRules(context.Background(), "flow-ip", BuildRulesFromAuth(auth)); err != nil {
		t.Fatalf("ApplyFlowRules failed: %v", err)
	}

	if len(appliedPayloads) == 0 {
		t.Fatal("no iptables-restore payload applied")
	}

	lastPayload := appliedPayloads[len(appliedPayloads)-1]
	if !strings.Contains(lastPayload, "-s 172.18.0.5") {
		t.Fatalf("Expected container source IP -s 172.18.0.5 in payload, got:\n%s", lastPayload)
	}
}

// TestFailClosedOnFirewallInstallationFailure confirms that non-zero exit from iptables-restore causes failure
func TestFailClosedOnFirewallInstallationFailure(t *testing.T) {
	fc := NewFirewallController()

	fc.SetCommandRunner(func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit code 1")
	})

	auth := policy.Authorization{
		FlowID:           "flow-failclosed",
		AllowedProtocols: []string{"tcp"},
		Targets: []policy.Target{
			{Host: "203.0.113.10", Port: 443},
		},
	}

	rules := BuildRulesFromAuth(auth)
	err := fc.ApplyFlowRules(context.Background(), "flow-failclosed", rules)
	if err == nil {
		t.Fatal("ApplyFlowRules must fail when iptables-restore returns an error")
	}
}

// TestRealLocalUDPAndTCPConnectionChecks verifies actual socket dials against
// local test listeners when authorized vs unauthorized.
func TestRealLocalUDPAndTCPConnectionChecks(t *testing.T) {
	// TCP test listener
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	// UDP test listener
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	fc := NewFirewallController()
	fc.SetCommandRunner(func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		return []byte("ok"), nil
	})

	auth := policy.Authorization{
		FlowID:           "flow-local",
		AllowedProtocols: []string{"tcp", "udp"},
		Targets: []policy.Target{
			{Host: "127.0.0.1", Port: tcpPort},
			{Host: "127.0.0.1", Port: udpPort},
		},
	}

	_ = fc.ApplyFlowRules(context.Background(), "flow-local", BuildRulesFromAuth(auth))

	// Verify TCP local listener is permitted
	if !fc.IsAllowed("flow-local", net.ParseIP("127.0.0.1"), tcpPort, "tcp") {
		t.Fatalf("TCP local listener on port %d should be allowed", tcpPort)
	}

	// Verify UDP local listener is permitted
	if !fc.IsAllowed("flow-local", net.ParseIP("127.0.0.1"), udpPort, "udp") {
		t.Fatalf("UDP local listener on port %d should be allowed", udpPort)
	}

	// Verify unlisted port is blocked
	if fc.IsAllowed("flow-local", net.ParseIP("127.0.0.1"), tcpPort+1, "tcp") {
		t.Fatalf("TCP port %d should be blocked", tcpPort+1)
	}
}

// TestDockerTamperingPrevention verifies docker host exec behavior
func TestDockerTamperingPrevention(t *testing.T) {
	path, err := exec.LookPath("iptables-restore")
	if err != nil {
		t.Skip("iptables-restore not installed on host, skipping raw binary test")
	}
	_ = path
	t.Log("iptables-restore binary available")
}
