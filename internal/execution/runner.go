package execution

import (
	"context"
	"time"
)

// ToolRequest is one argv execution inside a flow workspace.
type ToolRequest struct {
	FlowID         string
	Tool           string
	Argv           []string
	TimeoutSeconds int
}

// ToolOutput is the captured result of a tool request.
type ToolOutput struct {
	FlowID    string
	Tool      string
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Workspace string
	Artifacts []string
	Status    string
	Reason    string
}

// ToolRunner is the process boundary used by the API and by smoke tests.
// Prepare creates the per-flow workspace. Execute runs argv there.
type ToolRunner interface {
	Prepare(ctx context.Context, flowID string) (workspace string, err error)
	Execute(ctx context.Context, req ToolRequest) (ToolOutput, error)
}
