package execution

import (
	"os"
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

func TestStageWorkspaceInputsRewritesTargetListAndRequest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	t.Setenv("MIRAGE_WORKSPACE_HOST_ROOT", "")
	dir, err := EnsureWorkspace("flow-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "login.req")
	if err := os.WriteFile(outside, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged, err := StageWorkspaceInputs("flow-1", []string{"nuclei", "-l", "hosts.txt", "-o", "out.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if staged[2] != "/workspace/hosts.txt" || staged[4] != "/workspace/out.txt" {
		t.Fatalf("staged=%v", staged)
	}
	request, err := StageWorkspaceInputs("flow-1", []string{"sqlmap", "-r", outside, "--batch"})
	if err != nil {
		t.Fatal(err)
	}
	if request[2] != "/workspace/login.req" {
		t.Fatalf("request argv=%v", request)
	}
	if _, err := os.Stat(filepath.Join(dir, "login.req")); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceBindFromMountUsesDaemonPath(t *testing.T) {
	got := WorkspaceBindFromMount("/run/desktop/mnt/host/c/data/workspaces", "flow/abc")
	if got != filepath.Join("/run/desktop/mnt/host/c/data/workspaces", "flowabc") {
		t.Fatalf("bind source=%s", got)
	}
}
