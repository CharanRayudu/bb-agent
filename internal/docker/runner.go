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
	tool := req.Tool
	if tool == "" && len(req.Argv) > 0 {
		tool = req.Argv[0]
	}
	argv, err := execution.StageWorkspaceInputs(req.FlowID, req.Argv)
	workspace, _ := execution.EnsureWorkspace(req.FlowID)
	if err != nil {
		return failedOutput(req.FlowID, tool, workspace, nil, err), err
	}
	result, err := r.Sandbox.ExecuteArgvInFlow(ctx, req.FlowID, argv, req.TimeoutSeconds)
	artifacts := execution.RelativeWorkspaceFiles(workspace)
	if err != nil {
		out := failedOutput(req.FlowID, tool, workspace, artifacts, err)
		if result != nil {
			out.Stdout = result.Stdout
			out.Stderr = result.Stderr
			out.ExitCode = result.ExitCode
			out.Duration = result.Duration
		}
		return out, err
	}
	if result == nil {
		return failedOutput(req.FlowID, tool, workspace, artifacts, fmt.Errorf("tool returned no result")), nil
	}
	status := "ok"
	reason := ""
	if result.ExitCode != 0 {
		status = "failed"
		reason = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	return execution.ToolOutput{
		FlowID:    req.FlowID,
		Tool:      tool,
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
		ExitCode:  result.ExitCode,
		Duration:  result.Duration,
		Workspace: workspace,
		Artifacts: artifacts,
		Status:    status,
		Reason:    reason,
	}, nil
}

func failedOutput(flowID, tool, workspace string, artifacts []string, err error) execution.ToolOutput {
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	return execution.ToolOutput{
		FlowID:    flowID,
		Tool:      tool,
		Workspace: workspace,
		Artifacts: artifacts,
		Status:    "failed",
		Reason:    reason,
		ExitCode:  -1,
	}
}
