package docker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bb-agent/mirage/internal/execution"
)

var errNoSandbox = fmt.Errorf("flow sandbox is not configured")

// FlowRunner is the Docker implementation of execution.ToolRunner.
type FlowRunner struct {
	Sandbox *FlowSandbox
	Image   string
}

func (r FlowRunner) Prepare(ctx context.Context, flowID string) (string, error) {
	if r.Sandbox == nil {
		return "", errNoSandbox
	}
	bind, err := r.Sandbox.ResolveWorkspaceBind(ctx, flowID)
	if err != nil {
		return "", err
	}
	return r.Sandbox.EnsureWorkspace(ctx, flowID, bind, r.Image)
}

func (r FlowRunner) Execute(ctx context.Context, req execution.ToolRequest) (execution.ToolOutput, error) {
	if r.Sandbox == nil {
		return execution.ToolOutput{}, errNoSandbox
	}
	argv, err := execution.StageWorkspaceInputs(req.FlowID, req.Argv)
	if err != nil {
		workspace, _ := execution.EnsureWorkspace(req.FlowID)
		return execution.ToolOutput{Workspace: workspace}, err
	}
	result, err := r.Sandbox.ExecuteArgvInFlow(ctx, req.FlowID, argv, req.TimeoutSeconds)
	workspace, _ := execution.EnsureWorkspace(req.FlowID)
	artifacts := workspaceFiles(workspace)
	if err != nil {
		return execution.ToolOutput{Workspace: workspace, Artifacts: artifacts}, err
	}
	if result == nil {
		return execution.ToolOutput{Workspace: workspace, Artifacts: artifacts}, nil
	}
	return execution.ToolOutput{
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
		ExitCode:  result.ExitCode,
		Duration:  result.Duration,
		Workspace: workspace,
		Artifacts: artifacts,
	}, nil
}

func workspaceFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		out = append(out, filepath.Join(dir, entry.Name()))
	}
	return out
}
