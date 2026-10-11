package docker

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bb-agent/mirage/internal/execution"
)

func TestResolveWorkspaceBindOnTheHostUsesTheLocalDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	t.Setenv("MIRAGE_WORKSPACE_HOST_ROOT", "")
	fs := &FlowSandbox{}
	got, err := fs.ResolveWorkspaceBind(context.Background(), "flow/abc")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(filepath.Join(root, "flowabc"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bind source=%s want=%s", got, want)
	}
	if _, err := execution.EnsureWorkspace("flow/abc"); err != nil {
		t.Fatal(err)
	}
}
