package docker

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// SandboxProfile selects the appropriate container image for a scan type.
type SandboxProfile string

const (
	ProfileWeb     SandboxProfile = "web"     // Web application testing tools
	ProfileNetwork SandboxProfile = "network" // Network/infrastructure tools
	ProfileCloud   SandboxProfile = "cloud"   // Cloud security tools
	ProfileDefault SandboxProfile = "default" // General-purpose
)

// FlowSandboxConfig controls per-flow sandbox resource limits.
//
// Note on egress filtering: Docker's networking APIs do not provide a
// cheap host-level allow-list. If you need strict egress isolation, set
// NetworkMode to "none" (no outbound traffic) or to a user-managed
// network configured with iptables/nftables rules on the host. An
// in-process AllowedHosts field used to live here but was removed
// because it was never enforced and gave callers a false sense of
// security.
type FlowSandboxConfig struct {
	CPULimit    int64  // CPU quota (nanoCPUs, e.g., 2e9 = 2 CPUs)
	MemoryLimit int64  // Memory limit in bytes (e.g., 2<<30 = 2GB)
	DiskLimit   string // Disk limit (e.g., "5g")
	NetworkMode string // "bridge", "none", or a user-managed network name
}

// DefaultFlowConfig returns a sensible default sandbox configuration.
func DefaultFlowConfig() FlowSandboxConfig {
	return FlowSandboxConfig{
		CPULimit:    2e9,     // 2 CPUs
		MemoryLimit: 2 << 30, // 2 GB
		NetworkMode: "bridge",
	}
}

// FlowSandbox manages per-flow isolated Docker containers.
// Each flow gets its own ephemeral container with PID/network/IPC namespaces.
type FlowSandbox struct {
	client      *client.Client
	imageName   string
	containers  map[string]string // flowID -> containerID
	mu          sync.Mutex
	networkName string
}

// NewFlowSandbox creates a per-flow sandbox manager.
func NewFlowSandbox(dockerHost, imageName string) (*FlowSandbox, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if dockerHost != "" {
		opts = append(opts, client.WithHost(dockerHost))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping Docker daemon: %w", err)
	}

	return &FlowSandbox{
		client:      cli,
		imageName:   imageName,
		containers:  make(map[string]string),
		networkName: "mirage-net",
	}, nil
}

// CreateForFlow creates an isolated sandbox container for a specific flow.
func (fs *FlowSandbox) CreateForFlow(ctx context.Context, flowID string, profile SandboxProfile, config FlowSandboxConfig) (string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if already exists
	if containerID, ok := fs.containers[flowID]; ok {
		return containerID, nil
	}

	containerName := fmt.Sprintf("mirage-flow-%s", flowID[:8])
	image := fs.resolveImage(profile)

	netMode := config.NetworkMode
	if netMode == "" {
		netMode = "none"
	}
	if netMode == "bridge" {
		log.Printf("[sandbox] flow %s uses unrestricted bridge egress; set NetworkMode=\"none\" or configure host firewall for strict isolation", flowID[:8])
	}

	hostConfig := &container.HostConfig{
		Resources: container.Resources{
			NanoCPUs: config.CPULimit,
			Memory:   config.MemoryLimit,
		},
		NetworkMode: container.NetworkMode(netMode),
		SecurityOpt: []string{
			"no-new-privileges",
		},
	}

	resp, err := fs.client.ContainerCreate(ctx,
		&container.Config{
			Image: image,
			Cmd:   []string{"tail", "-f", "/dev/null"},
			Labels: map[string]string{
				"mirage.flow_id": flowID,
				"mirage.type":    "flow-sandbox",
				"mirage.profile": string(profile),
			},
		},
		hostConfig,
		&network.NetworkingConfig{},
		nil,
		containerName,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create flow sandbox: %w", err)
	}

	if err := fs.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		fs.client.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("failed to start flow sandbox: %w", err)
	}

	fs.containers[flowID] = resp.ID
	log.Printf("[sandbox] Created flow sandbox %s (%s) with profile %s", containerName, resp.ID[:12], profile)
	return resp.ID, nil
}

// ExecuteInFlow runs a shell command in a flow-specific sandbox via `bash -c`.
// See Sandbox.Execute for the same injection caveat: callers must validate
// any attacker-controlled input or switch to ExecuteArgvInFlow.
func (fs *FlowSandbox) ExecuteInFlow(ctx context.Context, flowID, command string, timeoutSec int) (*ExecResult, error) {
	fs.mu.Lock()
	containerID, ok := fs.containers[flowID]
	fs.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no sandbox for flow %s", flowID)
	}

	return executeInContainerArgv(ctx, fs.client, containerID, []string{"/bin/bash", "-c", command}, timeoutSec)
}

// ExecuteArgvInFlow runs an argv-form command in a flow-specific sandbox,
// bypassing the shell entirely. Preferred when any argument is derived
// from untrusted input.
func (fs *FlowSandbox) ExecuteArgvInFlow(ctx context.Context, flowID string, argv []string, timeoutSec int) (*ExecResult, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("ExecuteArgvInFlow: empty argv")
	}
	fs.mu.Lock()
	containerID, ok := fs.containers[flowID]
	fs.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no sandbox for flow %s", flowID)
	}

	return executeInContainerArgv(ctx, fs.client, containerID, argv, timeoutSec)
}

// DestroyForFlow removes the sandbox container for a completed flow.
func (fs *FlowSandbox) DestroyForFlow(ctx context.Context, flowID string) error {
	fs.mu.Lock()
	containerID, ok := fs.containers[flowID]
	if !ok {
		fs.mu.Unlock()
		return nil
	}
	delete(fs.containers, flowID)
	fs.mu.Unlock()

	timeout := 10
	if err := fs.client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		log.Printf("[sandbox] Warning: stop failed for %s: %v", containerID[:12], err)
	}

	if err := fs.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("failed to remove flow sandbox: %w", err)
	}

	log.Printf("[sandbox] Destroyed flow sandbox for %s", flowID[:8])
	return nil
}

// CleanupAll removes all flow sandboxes (called on shutdown).
func (fs *FlowSandbox) CleanupAll(ctx context.Context) {
	fs.mu.Lock()
	flowIDs := make([]string, 0, len(fs.containers))
	for fid := range fs.containers {
		flowIDs = append(flowIDs, fid)
	}
	fs.mu.Unlock()

	for _, fid := range flowIDs {
		if err := fs.DestroyForFlow(ctx, fid); err != nil {
			log.Printf("[sandbox] Cleanup error for flow %s: %v", fid[:8], err)
		}
	}
}

// ActiveFlows returns the number of active flow sandboxes.
func (fs *FlowSandbox) ActiveFlows() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.containers)
}

func (fs *FlowSandbox) resolveImage(profile SandboxProfile) string {
	switch profile {
	case ProfileWeb:
		return fs.imageName // mirage-tools:latest is web-focused
	case ProfileNetwork:
		return fs.imageName + "-network"
	case ProfileCloud:
		return fs.imageName + "-cloud"
	default:
		return fs.imageName
	}
}

// executeInContainer is a shared helper for running shell commands in any
// container. Deprecated: prefer executeInContainerArgv with an explicit
// argv to avoid shell injection.
func executeInContainer(ctx context.Context, cli *client.Client, containerID, command string, timeoutSec int) (*ExecResult, error) {
	return executeInContainerArgv(ctx, cli, containerID, []string{"/bin/bash", "-c", command}, timeoutSec)
}

// executeInContainerArgv runs an explicit argv in the container without
// invoking a shell parser.
func executeInContainerArgv(ctx context.Context, cli *client.Client, containerID string, argv []string, timeoutSec int) (*ExecResult, error) {
	start := time.Now()

	if timeoutSec <= 0 {
		timeoutSec = 300
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	execConfig := container.ExecOptions{
		Cmd:          argv,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	execResp, err := cli.ContainerExecCreate(execCtx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec instance: %w", err)
	}

	attachResp, err := cli.ContainerExecAttach(execCtx, execResp.ID, container.ExecStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer attachResp.Close()

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		var stdoutBuf, stderrBuf bytes.Buffer
		_, err := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attachResp.Reader)
		if err != nil {
			errCh <- err
			return
		}

		var exitCode int
		for {
			inspect, err := cli.ContainerExecInspect(execCtx, execResp.ID)
			if err != nil {
				errCh <- err
				return
			}
			if !inspect.Running {
				exitCode = inspect.ExitCode
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		errCh <- &SandboxError{
			Stdout:   strings.TrimSpace(stdoutBuf.String()),
			Stderr:   strings.TrimSpace(stderrBuf.String()),
			ExitCode: exitCode,
		}
	}()

	select {
	case res := <-errCh:
		if sandboxErr, ok := res.(*SandboxError); ok {
			return &ExecResult{
				Stdout:   sandboxErr.Stdout,
				Stderr:   sandboxErr.Stderr,
				ExitCode: sandboxErr.ExitCode,
				Duration: time.Since(start),
			}, nil
		}
		if res != nil {
			return nil, fmt.Errorf("exec error: %w", res)
		}
	case <-execCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &ExecResult{
			Stderr:   "command timed out",
			ExitCode: -1,
			Duration: time.Since(start),
		}, nil
	}

	return nil, fmt.Errorf("unexpected execution completion")
}
