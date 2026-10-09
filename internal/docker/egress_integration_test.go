package docker

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/google/uuid"
)

func TestFlowNetworkDropsUnapprovedTCPAndUDP(t *testing.T) {
	if _, err := exec.Command("docker", "version").CombinedOutput(); err != nil {
		t.Fatalf("docker is required to prove network egress isolation: %v", err)
	}
	build := exec.Command("docker", "build", "-t", "mirage-egress-fixture:local", filepath.Join("..", "..", "build", "egress-fixture"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build egress fixture: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	fs, err := NewFlowSandbox("", "mirage-egress-fixture:local")
	if err != nil {
		t.Fatal(err)
	}
	flowID := uuid.NewString()
	cfg := DefaultFlowConfig()
	cfg.Image = "mirage-egress-fixture:local"
	cfg.MemoryLimit = 128 << 20
	cfg.CPULimit = 5e8
	if _, err := fs.CreateForFlow(ctx, flowID, ProfileDefault, cfg); err != nil {
		t.Fatal(err)
	}
	netName := fs.NetworkName(flowID)
	allowedID := ""
	deniedID := ""
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if allowedID != "" {
			_ = fs.client.ContainerRemove(cleanCtx, allowedID, container.RemoveOptions{Force: true})
		}
		if deniedID != "" {
			_ = fs.client.ContainerRemove(cleanCtx, deniedID, container.RemoveOptions{Force: true})
		}
		_ = fs.DestroyForFlow(cleanCtx, flowID)
	})

	allowedID, err = startPeer(ctx, fs, netName, "mirage-egress-allowed-"+shortFlowID(flowID))
	if err != nil {
		t.Fatal(err)
	}
	deniedID, err = startPeer(ctx, fs, netName, "mirage-egress-denied-"+shortFlowID(flowID))
	if err != nil {
		t.Fatal(err)
	}
	allowedIP, err := peerIP(ctx, fs, allowedID, netName)
	if err != nil {
		t.Fatal(err)
	}
	deniedIP, err := peerIP(ctx, fs, deniedID, netName)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.EnforceEgress(ctx, flowID, []EgressPermit{{IP: net.ParseIP(allowedIP), Port: 8080}}); err != nil {
		t.Fatal(err)
	}

	if err := waitHTTP(ctx, fs, flowID, allowedIP); err != nil {
		t.Fatal(err)
	}
	if code, err := curlCode(ctx, fs, flowID, deniedIP, 8080); err != nil || code == 0 {
		t.Fatalf("excluded destination was reachable, exit=%d err=%v", code, err)
	}
	if code, err := curlCode(ctx, fs, flowID, allowedIP, 9); err != nil || code == 0 {
		t.Fatalf("unapproved port was reachable, exit=%d err=%v", code, err)
	}
	udpAllowed, err := fs.ExecuteArgvInFlow(ctx, flowID, []string{"iptables", "-C", "MIRAGE_EGRESS", "-d", allowedIP, "-p", "udp", "--dport", "8080", "-j", "ACCEPT"}, 15)
	if err != nil || udpAllowed.ExitCode != 0 {
		t.Fatalf("udp to the authorized port is not allowed: %+v err=%v", udpAllowed, err)
	}
	udpDenied, err := fs.ExecuteArgvInFlow(ctx, flowID, []string{"iptables", "-C", "MIRAGE_EGRESS", "-d", deniedIP, "-p", "udp", "--dport", "8080", "-j", "ACCEPT"}, 15)
	if err != nil {
		t.Fatal(err)
	}
	if udpDenied.ExitCode == 0 {
		t.Fatal("udp to the excluded destination is allowed")
	}
}

func startPeer(ctx context.Context, fs *FlowSandbox, netName, name string) (string, error) {
	resp, err := fs.client.ContainerCreate(ctx, &container.Config{
		Image: "mirage-egress-fixture:local",
		Cmd: []string{"sh", "-c", `while true; do printf 'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok' | nc -l -p 8080; done`},
		Labels: map[string]string{
			"mirage.type": "egress-fixture",
		},
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
		Resources:   container.Resources{Memory: 64 << 20},
	}, &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
		netName: {},
	}}, nil, name)
	if err != nil {
		return "", err
	}
	if err := fs.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func peerIP(ctx context.Context, fs *FlowSandbox, id, netName string) (string, error) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		inspect, err := fs.client.ContainerInspect(ctx, id)
		if err != nil {
			return "", err
		}
		if inspect.NetworkSettings != nil {
			if endpoint, ok := inspect.NetworkSettings.Networks[netName]; ok && endpoint != nil && endpoint.IPAddress != "" {
				return endpoint.IPAddress, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", fmt.Errorf("container %s has no address on %s", id, netName)
}

func waitHTTP(ctx context.Context, fs *FlowSandbox, flowID, ip string) error {
	var last int
	var lastErr error
	for i := 0; i < 8; i++ {
		last, lastErr = curlCode(ctx, fs, flowID, ip, 8080)
		if lastErr == nil && last == 0 {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("authorized destination was not reachable, exit=%d err=%v", last, lastErr)
}

func curlCode(ctx context.Context, fs *FlowSandbox, flowID, ip string, port int) (int, error) {
	result, err := fs.ExecuteArgvInFlow(ctx, flowID, []string{
		"curl", "-sS", "-o", "/dev/null", "--max-time", "3",
		fmt.Sprintf("http://%s:%d/", ip, port),
	}, 15)
	if err != nil {
		return -1, err
	}
	return result.ExitCode, nil
}
