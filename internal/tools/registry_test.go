package tools

import (
	"strings"
	"testing"
)

func TestBuildBrowserScriptCommand_ConfiguresNodePathAndCleanup(t *testing.T) {
	cmd := buildBrowserScriptCommand("ZW5jb2RlZA==")
	requiredParts := []string{
		"npm root -g",
		"NODE_PATH=",
		"/usr/local/lib/node_modules",
		"PLAYWRIGHT_BROWSERS_PATH",
		"rm -f \"$script_path\"",
	}
	for _, part := range requiredParts {
		if !strings.Contains(cmd, part) {
			t.Fatalf("expected browser command to contain %q, got %s", part, cmd)
		}
	}
}
