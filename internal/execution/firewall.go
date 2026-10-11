package execution

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// NetworkRule is one host-firewall allow for packets leaving a flow container.
type NetworkRule struct {
	FlowID      string
	ContainerIP net.IP
	Protocol    string
	IP          net.IP
	Port        int
}

// FirewallController installs egress rules on the Docker host so a scanner
// container cannot change its own policy. Rules are keyed by the container
// source address and are replaced atomically.
type FirewallController struct {
	mu          sync.Mutex
	rules       map[string][]NetworkRule
	containerIP map[string]net.IP
	cmdRunner   func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
	helperImage string
	fallback    bool
}

// NewFirewallController creates a host firewall. helperImage is the container
// image used to run iptables when the host binary is not on PATH.
func NewFirewallController(helperImage string) *FirewallController {
	return &FirewallController{
		rules:       map[string][]NetworkRule{},
		containerIP: map[string]net.IP{},
		helperImage: helperImage,
		fallback:    helperImage != "",
		cmdRunner: func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			if len(stdin) > 0 {
				cmd.Stdin = bytes.NewReader(stdin)
			}
			return cmd.CombinedOutput()
		},
	}
}

// SetCommandRunner replaces process execution. Tests use this to avoid iptables.
func (fc *FirewallController) SetCommandRunner(fn func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)) {
	if fc == nil {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.cmdRunner = fn
	fc.fallback = false
}

// BindContainerIP records the source address host rules must match.
func (fc *FirewallController) BindContainerIP(flowID string, ip net.IP) {
	if fc == nil || flowID == "" || ip == nil {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.containerIP[flowID] = ip
}

// ApplyFlowRules replaces one flow's allow-list and installs the host rules.
// An empty list still drops every forwarded packet from that container.
func (fc *FirewallController) ApplyFlowRules(ctx context.Context, flowID string, rules []NetworkRule) error {
	if fc == nil {
		return fmt.Errorf("host firewall is not configured")
	}
	if flowID == "" {
		return fmt.Errorf("flowID cannot be empty")
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.containerIP[flowID] == nil {
		for _, rule := range rules {
			if rule.ContainerIP != nil {
				fc.containerIP[flowID] = rule.ContainerIP
				break
			}
		}
	}
	if fc.containerIP[flowID] == nil {
		return fmt.Errorf("container IP is not bound for flow %s", flowID)
	}
	for _, rule := range rules {
		if rule.IP == nil || rule.Port <= 0 {
			return fmt.Errorf("firewall rule for flow %s is missing a destination", flowID)
		}
		switch strings.ToLower(rule.Protocol) {
		case "tcp", "udp":
		default:
			return fmt.Errorf("firewall rule for flow %s has protocol %q", flowID, rule.Protocol)
		}
	}
	copied := make([]NetworkRule, len(rules))
	copy(copied, rules)
	fc.rules[flowID] = copied
	if err := fc.restoreLocked(ctx, fc.payloadLocked()); err != nil {
		return err
	}
	return fc.ensureJumpLocked(ctx)
}

// RevokeFlowRules removes a flow's host rules and reinstalls the remaining set.
func (fc *FirewallController) RevokeFlowRules(ctx context.Context, flowID string) error {
	if fc == nil {
		return nil
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.rules, flowID)
	delete(fc.containerIP, flowID)
	if err := fc.restoreLocked(ctx, fc.payloadLocked()); err != nil {
		return err
	}
	return nil
}

// IsAllowed reports whether the in-memory rules permit this socket.
func (fc *FirewallController) IsAllowed(flowID string, ip net.IP, port int, protocol string) bool {
	if fc == nil || ip == nil || port <= 0 {
		return false
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for _, rule := range fc.rules[flowID] {
		if rule.IP == nil || !rule.IP.Equal(ip) || rule.Port != port {
			continue
		}
		if !strings.EqualFold(normalizeProto(rule.Protocol), normalizeProto(protocol)) {
			continue
		}
		return true
	}
	return false
}

func (fc *FirewallController) payloadLocked() string {
	var buf bytes.Buffer
	buf.WriteString("*filter\n")
	buf.WriteString(":MIRAGE-EGRESS - [0:0]\n")
	buf.WriteString("-F MIRAGE-EGRESS\n")
	for flowID, rules := range fc.rules {
		src := fc.containerIP[flowID]
		if src == nil {
			continue
		}
		comment := safeFlowComment(flowID)
		for _, rule := range rules {
			if rule.IP == nil || rule.Port <= 0 {
				continue
			}
			proto := normalizeProto(rule.Protocol)
			fmt.Fprintf(&buf, "-A MIRAGE-EGRESS -s %s -d %s -p %s --dport %d -m comment --comment \"flow:%s\" -j ACCEPT\n",
				src.String(), rule.IP.String(), proto, rule.Port, comment)
		}
		fmt.Fprintf(&buf, "-A MIRAGE-EGRESS -s %s -m comment --comment \"flow:%s\" -j DROP\n", src.String(), comment)
	}
	buf.WriteString("-A MIRAGE-EGRESS -j RETURN\n")
	buf.WriteString("COMMIT\n")
	return buf.String()
}

func (fc *FirewallController) restoreLocked(ctx context.Context, payload string) error {
	_, err := fc.runLocked(ctx, []string{"iptables-restore", "--noflush"}, []byte(payload))
	if err != nil {
		return fmt.Errorf("apply host firewall: %w", err)
	}
	return nil
}

func (fc *FirewallController) ensureJumpLocked(ctx context.Context) error {
	for _, chain := range []string{"DOCKER-USER", "FORWARD"} {
		if _, err := fc.runLocked(ctx, []string{"iptables", "-C", chain, "-j", "MIRAGE-EGRESS"}, nil); err == nil {
			return nil
		}
	}
	for _, chain := range []string{"DOCKER-USER", "FORWARD"} {
		if _, err := fc.runLocked(ctx, []string{"iptables", "-I", chain, "1", "-j", "MIRAGE-EGRESS"}, nil); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not attach MIRAGE-EGRESS to DOCKER-USER or FORWARD")
}

func (fc *FirewallController) runLocked(ctx context.Context, argv []string, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty firewall command")
	}
	out, err := fc.cmdRunner(ctx, argv[0], argv[1:], stdin)
	if err == nil {
		return out, nil
	}
	if !fc.fallback || fc.helperImage == "" {
		return out, fmt.Errorf("%s: %s: %w", strings.Join(argv, " "), strings.TrimSpace(string(out)), err)
	}
	dockerArgs := []string{"run", "--rm", "-i", "--privileged", "--network", "host", fc.helperImage}
	dockerArgs = append(dockerArgs, argv...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	fallbackOut, fallbackErr := cmd.CombinedOutput()
	if fallbackErr != nil {
		return fallbackOut, fmt.Errorf("%s via %s: %s: %w", strings.Join(argv, " "), fc.helperImage, strings.TrimSpace(string(fallbackOut)), fallbackErr)
	}
	return fallbackOut, nil
}

func safeFlowComment(flowID string) string {
	var buf strings.Builder
	for _, r := range flowID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			buf.WriteRune(r)
		}
		if buf.Len() == 32 {
			break
		}
	}
	if buf.Len() == 0 {
		return "flow"
	}
	return buf.String()
}
