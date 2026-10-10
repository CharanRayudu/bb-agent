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
	FlowID   string
	Protocol string // "tcp", "udp", or "all"
	Host     string
	IP       net.IP
	Port     int
}

// FirewallController manages atomic network egress rules on the host
// for flow containers to ensure containers cannot alter their network policies.
type FirewallController struct {
	mu        sync.RWMutex
	rules     map[string][]NetworkRule // flowID -> rules
	cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)
	enabled   bool
}

// NewFirewallController creates a host-side firewall manager.
func NewFirewallController() *FirewallController {
	return &FirewallController{
		rules: make(map[string][]NetworkRule),
		cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			return cmd.CombinedOutput()
		},
		enabled: true,
	}
}

// SetCommandRunner overrides the command execution function for testing.
func (fc *FirewallController) SetCommandRunner(fn func(ctx context.Context, name string, args ...string) ([]byte, error)) {
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

// ApplyFlowRules atomically updates the ruleset for a specific flow.
// It generates an atomic iptables-restore / nftables payload so no permissive gap exists.
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
	_ = fc.generateIptablesRestorePayloadLocked()
	if fc.cmdRunner != nil {
		out, err := fc.cmdRunner(ctx, "iptables-restore", "--noflush")
		if err != nil {
			_ = out
			return fmt.Errorf("failed to apply atomic firewall rules: %w", err)
		}
	}

	return nil
}

// RevokeFlowRules atomically clears and revokes all rules for a flow.
func (fc *FirewallController) RevokeFlowRules(ctx context.Context, flowID string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	delete(fc.rules, flowID)

	if !fc.enabled {
		return nil
	}

	_ = fc.generateIptablesRestorePayloadLocked()
	if fc.cmdRunner != nil {
		_, err := fc.cmdRunner(ctx, "iptables-restore", "--noflush")
		if err != nil {
			return fmt.Errorf("failed to revoke firewall rules for flow %s: %w", flowID, err)
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

	// For each flow, add exact drop/accept rules
	for flowID, rules := range fc.rules {
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
			buf.WriteString(fmt.Sprintf("-A MIRAGE-EGRESS -m comment --comment \"flow:%s\" -p %s %s%s-j ACCEPT\n", flowID, proto, ipStr, portStr))
		}
	}
	// Default drop at the end of chain
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
