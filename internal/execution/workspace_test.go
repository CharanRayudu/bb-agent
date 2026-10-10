package execution

import (
	"path/filepath"
	"testing"
)

func TestRewriteWorkspaceOutputsKeepsAbsolutePaths(t *testing.T) {
	got := RewriteWorkspaceOutputs([]string{"nuclei", "-o", "scan.txt", "-u", "http://example.com"})
	if got[2] != "/workspace/scan.txt" {
		t.Fatalf("output path=%s", got[2])
	}
	abs := RewriteWorkspaceOutputs([]string{"curl", "-o", "/tmp/scan.txt", "http://example.com"})
	if abs[2] != "/tmp/scan.txt" {
		t.Fatalf("absolute path changed to %s", abs[2])
	}
}

func TestWorkspaceBindSourceUsesHostRoot(t *testing.T) {
	t.Setenv("MIRAGE_WORKSPACE_ROOT", t.TempDir())
	host := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_HOST_ROOT", host)
	got, err := WorkspaceBindSource("flow/abc")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(host, "flowabc") {
		t.Fatalf("bind source=%s", got)
	}
}

func TestWorkspaceBindFromMountUsesDaemonPath(t *testing.T) {
	got := WorkspaceBindFromMount("/run/desktop/mnt/host/c/data/workspaces", "flow/abc")
	if got != filepath.Join("/run/desktop/mnt/host/c/data/workspaces", "flowabc") {
		t.Fatalf("bind source=%s", got)
	}
}
