package docker

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/docker/docker/client"
)

// EgressPermit is one destination socket the flow container may open.
type EgressPermit struct {
	IP   net.IP
	Port int
}

// EnforceEgress installs an OUTPUT filter inside the flow container.
// Packets to any other IP or port are dropped in that network namespace.
func (fs *FlowSandbox) EnforceEgress(ctx context.Context, flowID string, permits []EgressPermit) error {
	if fs == nil {
		return fmt.Errorf("flow sandbox is not configured")
	}
	fs.mu.Lock()
	containerID, ok := fs.containers[flowID]
	fs.mu.Unlock()
	if !ok {
		return fmt.Errorf("no sandbox for flow %s", flowID)
	}
	return applyEgressFilter(ctx, fs.client, containerID, permits)
}

func applyEgressFilter(ctx context.Context, cli *client.Client, containerID string, permits []EgressPermit) error {
	if err := applyFamily(ctx, cli, containerID, "iptables", permits, false); err != nil {
		return err
	}
	return applyFamily(ctx, cli, containerID, "ip6tables", permits, true)
}

func applyFamily(ctx context.Context, cli *client.Client, containerID, binary string, permits []EgressPermit, v6 bool) error {
	commands := [][]string{
		{binary, "-N", "MIRAGE_EGRESS"},
		{binary, "-F", "MIRAGE_EGRESS"},
		{binary, "-A", "MIRAGE_EGRESS", "-o", "lo", "-j", "ACCEPT"},
	}
	if !v6 {
		commands = append(commands,
			[]string{binary, "-A", "MIRAGE_EGRESS", "-d", "127.0.0.11", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{binary, "-A", "MIRAGE_EGRESS", "-d", "127.0.0.11", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		)
	}
	seenICMP := map[string]bool{}
	for _, permit := range permits {
		if permit.IP == nil || permit.Port <= 0 {
			continue
		}
		is6 := permit.IP.To4() == nil
		if is6 != v6 {
			continue
		}
		ip := permit.IP.String()
		port := fmt.Sprintf("%d", permit.Port)
		commands = append(commands,
			[]string{binary, "-A", "MIRAGE_EGRESS", "-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
			[]string{binary, "-A", "MIRAGE_EGRESS", "-d", ip, "-p", "udp", "--dport", port, "-j", "ACCEPT"},
		)
		if !seenICMP[ip] {
			seenICMP[ip] = true
			if v6 {
				commands = append(commands, []string{binary, "-A", "MIRAGE_EGRESS", "-d", ip, "-p", "icmpv6", "-j", "ACCEPT"})
			} else {
				commands = append(commands, []string{binary, "-A", "MIRAGE_EGRESS", "-d", ip, "-p", "icmp", "-j", "ACCEPT"})
			}
		}
	}
	commands = append(commands, []string{binary, "-A", "MIRAGE_EGRESS", "-j", "DROP"})
	for i, argv := range commands {
		if err := runFilter(ctx, cli, containerID, argv, i == 0); err != nil {
			return err
		}
	}
	check, err := executeInContainerArgv(ctx, cli, containerID, []string{binary, "-C", "OUTPUT", "-j", "MIRAGE_EGRESS"}, 15)
	if err != nil {
		return err
	}
	if check.ExitCode != 0 {
		if err := runFilter(ctx, cli, containerID, []string{binary, "-I", "OUTPUT", "1", "-j", "MIRAGE_EGRESS"}, false); err != nil {
			return err
		}
	}
	return nil
}

func runFilter(ctx context.Context, cli *client.Client, containerID string, argv []string, ignoreExists bool) error {
	result, err := executeInContainerArgv(ctx, cli, containerID, argv, 15)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	if result.ExitCode == 0 {
		return nil
	}
	text := result.Stderr + result.Stdout
	if ignoreExists && strings.Contains(strings.ToLower(text), "already exists") {
		return nil
	}
	if strings.TrimSpace(text) == "" {
		text = fmt.Sprintf("exit %d", result.ExitCode)
	}
	return fmt.Errorf("%s: %s", strings.Join(argv, " "), strings.TrimSpace(text))
}
