package execution

import "context"

// ToolRequest is one argv execution inside a flow workspace.
type ToolRequest struct {
	FlowID         string
	Argv           []string
	TimeoutSeconds int
}

// ToolOutput is the captured result of a tool request.
type ToolOutput struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Workspace string
}

// ToolRunner is the process boundary used by the API and by smoke tests.
// Prepare creates the per-flow workspace. Execute runs argv there.
type ToolRunner interface {
	Prepare(ctx context.Context, flowID string) (workspace string, err error)
	Execute(ctx context.Context, req ToolRequest) (ToolOutput, error)
}
