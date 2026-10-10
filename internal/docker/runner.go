package docker

import (
	"context"
	"fmt"

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
	dir, err := execution.EnsureWorkspace(flowID)
	if err != nil {
		return "", err
	}
	return r.Sandbox.EnsureWorkspace(ctx, flowID, dir, r.Image)
}

func (r FlowRunner) Execute(ctx context.Context, req execution.ToolRequest) (execution.ToolOutput, error) {
	if r.Sandbox == nil {
		return execution.ToolOutput{}, errNoSandbox
	}
	argv := execution.RewriteWorkspaceOutputs(req.Argv)
	result, err := r.Sandbox.ExecuteArgvInFlow(ctx, req.FlowID, argv, req.TimeoutSeconds)
	workspace, _ := execution.EnsureWorkspace(req.FlowID)
	if err != nil {
		return execution.ToolOutput{Workspace: workspace}, err
	}
	if result == nil {
		return execution.ToolOutput{Workspace: workspace}, nil
	}
	return execution.ToolOutput{
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
		ExitCode:  result.ExitCode,
		Workspace: workspace,
	}, nil
}
