package execution

import "testing"

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
