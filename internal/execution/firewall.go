package execution

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/bb-agent/mirage/internal/policy"
)

// NetworkRule represents a permitted egress rule for a flow.
type NetworkRule struct {
	FlowID      string
	ContainerIP net.IP
	Protocol    string // "tcp", "udp", or "all"
	Host        string
	IP          net.IP
	Port        int
}

// FirewallController manages atomic network egress rules on the host
// for flow containers to ensure containers cannot alter their network policies.
type FirewallController struct {
	mu          sync.RWMutex
	rules       map[string][]NetworkRule // flowID -> rules
	containerIP map[string]net.IP        // flowID -> container IP
	cmdRunner   func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
	enabled     bool
}

// NewFirewallController creates a host-side firewall manager.
func NewFirewallController() *FirewallController {
	return &FirewallController{
		rules:       make(map[string][]NetworkRule),
		containerIP: make(map[string]net.IP),
		cmdRunner: func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			if len(stdin) > 0 {
				cmd.Stdin = bytes.NewReader(stdin)
			}
			return cmd.CombinedOutput()
		},
		enabled: true,
	}
}

// SetCommandRunner overrides the command execution function for testing.
func (fc *FirewallController) SetCommandRunner(fn func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.cmdRunner = fn
}

// SetEnabled toggles firewall rule application.
func (fc *FirewallController) SetEnabled(enabled bool) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.enabled = enabled
}

// BindContainerIP associates a container's internal IP with a flow ID.
func (fc *FirewallController) BindContainerIP(flowID string, ip net.IP) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if flowID != "" && ip != nil {
		fc.containerIP[flowID] = ip
	}
}

// ApplyFlowRules atomically updates the ruleset for a specific flow.
// It generates an atomic iptables-restore payload and passes it via stdin to iptables-restore.
func (fc *FirewallController) ApplyFlowRules(ctx context.Context, flowID string, rules []NetworkRule) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if flowID == "" {
		return fmt.Errorf("flowID cannot be empty")
	}

	// Make a copy of rules
	cp := make([]NetworkRule, len(rules))
	copy(cp, rules)
	fc.rules[flowID] = cp

	if !fc.enabled {
		return nil
	}

	// Generate atomic iptables payload
	payload := fc.generateIptablesRestorePayloadLocked()
	if fc.cmdRunner != nil {
		out, err := fc.cmdRunner(ctx, "iptables-restore", []string{"--noflush"}, []byte(payload))
		if err != nil {
			return fmt.Errorf("failed to apply atomic firewall rules (out: %s): %w", string(out), err)
		}
	}

	return nil
}

// RevokeFlowRules atomically clears and revokes all rules for a flow.
func (fc *FirewallController) RevokeFlowRules(ctx context.Context, flowID string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	delete(fc.rules, flowID)
	delete(fc.containerIP, flowID)

	if !fc.enabled {
		return nil
	}

	payload := fc.generateIptablesRestorePayloadLocked()
	if fc.cmdRunner != nil {
		out, err := fc.cmdRunner(ctx, "iptables-restore", []string{"--noflush"}, []byte(payload))
		if err != nil {
			return fmt.Errorf("failed to revoke firewall rules for flow %s (out: %s): %w", flowID, string(out), err)
		}
	}
	return nil
}

// IsAllowed checks if a flow is permitted to egress to a specific IP, port, and protocol (tcp/udp).
func (fc *FirewallController) IsAllowed(flowID string, ip net.IP, port int, protocol string) bool {
	fc.mu.RLock()
	rules, exists := fc.rules[flowID]
	fc.mu.RUnlock()

	if !exists || len(rules) == 0 {
		return false
	}

	proto := strings.ToLower(protocol)
	for _, r := range rules {
		if r.IP != nil && !r.IP.Equal(ip) {
			continue
		}
		if r.Port != 0 && r.Port != port {
			continue
		}
		if r.Protocol != "" && r.Protocol != "all" && !strings.EqualFold(r.Protocol, proto) {
			continue
		}
		return true
	}
	return false
}

// generateIptablesRestorePayloadLocked builds an atomic iptables-restore script.
func (fc *FirewallController) generateIptablesRestorePayloadLocked() string {
	var buf bytes.Buffer
	buf.WriteString("*filter\n")
	buf.WriteString(":MIRAGE-EGRESS - [0:0]\n")

	// Flush existing rules in MIRAGE-EGRESS chain for clean update
	buf.WriteString("-F MIRAGE-EGRESS\n")

	// For each flow, add exact drop/accept rules matching container source IP and destination IP/port
	for flowID, rules := range fc.rules {
		containerIP := fc.containerIP[flowID]
		srcStr := ""
		if containerIP != nil {
			srcStr = fmt.Sprintf("-s %s ", containerIP.String())
		}
		for _, r := range rules {
			proto := strings.ToLower(r.Protocol)
			if proto == "" || proto == "all" {
				proto = "all"
			}
			ipStr := ""
			if r.IP != nil {
				ipStr = fmt.Sprintf("-d %s ", r.IP.String())
			}
			portStr := ""
			if r.Port > 0 && (proto == "tcp" || proto == "udp") {
				portStr = fmt.Sprintf("--dport %d ", r.Port)
			}
			buf.WriteString(fmt.Sprintf("-A MIRAGE-EGRESS %s-m comment --comment \"flow:%s\" -p %s %s%s-j ACCEPT\n", srcStr, flowID, proto, ipStr, portStr))
		}
	}
	// Default drop for MIRAGE-EGRESS chain
	buf.WriteString("-A MIRAGE-EGRESS -j DROP\n")
	buf.WriteString("COMMIT\n")
	return buf.String()
}

// BuildRulesFromAuth converts a policy.Authorization into network rules.
func BuildRulesFromAuth(auth policy.Authorization) []NetworkRule {
	var rules []NetworkRule
	protocols := auth.AllowedProtocols
	if len(protocols) == 0 {
		protocols = []string{"tcp", "udp"}
	}

	for _, target := range auth.Targets {
		ip := net.ParseIP(target.Host)
		for _, proto := range protocols {
			rules = append(rules, NetworkRule{
				FlowID:   auth.FlowID,
				Protocol: proto,
				Host:     target.Host,
				IP:       ip,
				Port:     target.Port,
			})
		}
	}
	return rules
}
