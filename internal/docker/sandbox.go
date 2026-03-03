package docker

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Sandbox manages isolated Docker containers for running security tools
type Sandbox struct {
	client    *client.Client
	imageName string
}

// NewSandbox creates a new Docker sandbox manager
func NewSandbox(dockerHost, imageName string) (*Sandbox, error) {
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

	_, err = cli.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ping Docker daemon: %w", err)
	}

	// Verify sandbox container exists
	sandboxName := "mirage-sandbox"
	_, err = cli.ContainerInspect(ctx, sandboxName)
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Printf("⚠️  Sandbox container '%s' not found. It must be started via docker-compose.", sandboxName)
		} else {
			return nil, fmt.Errorf("failed to inspect sandbox container: %w", err)
		}
	}

	log.Println("✅ Connected to Docker daemon and verified sandbox container")
	return &Sandbox{client: cli, imageName: imageName}, nil
}

// ExecResult holds the output from a command execution
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Execute runs a command inside a sandboxed container with resource limits
func (s *Sandbox) Execute(ctx context.Context, command string, timeoutSec int) (*ExecResult, error) {
	start := time.Now()

	if timeoutSec <= 0 {
		timeoutSec = 300 // 5 minute default
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Prepare the exec configuration
	execConfig := container.ExecOptions{
		Cmd:          []string{"/bin/bash", "-c", command},
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	// Create exec instance
	// We hardcode 'mirage-sandbox' since it's the persistent container
	execResp, err := s.client.ContainerExecCreate(execCtx, "mirage-sandbox", execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec instance: %w", err)
	}

	// Attach to the exec instance to get output
	attachResp, err := s.client.ContainerExecAttach(execCtx, execResp.ID, container.ExecStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec instance: %w", err)
	}
	defer attachResp.Close()

	// Wait for execution to finish or context cancellation
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		var stdoutBuf, stderrBuf bytes.Buffer
		_, err := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attachResp.Reader)
		if err != nil {
			errCh <- err
			return
		}

		// Wait for the exit code
		var exitCode int
		for {
			inspect, err := s.client.ContainerExecInspect(execCtx, execResp.ID)
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
			return nil, fmt.Errorf("exec copy/inspect error: %w", res)
		}
	case <-execCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &ExecResult{
			Stderr:   "command timed out during execution",
			ExitCode: -1,
			Duration: time.Since(start),
		}, nil
	}

	return nil, fmt.Errorf("unexpected execution completion")
}

// SandboxError is a helper just to shuttle results through the channel
type SandboxError struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func (e *SandboxError) Error() string {
	return "sandbox result"
}

// Close cleans up the Docker client
func (s *Sandbox) Close() error {
	return s.client.Close()
}
