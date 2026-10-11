package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutionV2FollowsTheEnvironment(t *testing.T) {
	t.Setenv("MIRAGE_EXECUTION_V2", "true")
	on, err := Load()
	if err != nil || !on.ExecutionV2 {
		t.Fatalf("explicit true did not enable v2: %+v %v", on, err)
	}
	if !strings.Contains(on.ExecutionModeStatus(), "execution mode v2") {
		t.Fatal(on.ExecutionModeStatus())
	}

	t.Setenv("MIRAGE_EXECUTION_V2", "false")
	off, err := Load()
	if err != nil || off.ExecutionV2 {
		t.Fatalf("explicit false did not keep legacy mode: %+v %v", off, err)
	}
	if !strings.Contains(off.ExecutionModeStatus(), "execution mode legacy") {
		t.Fatal(off.ExecutionModeStatus())
	}

	os.Unsetenv("MIRAGE_EXECUTION_V2")
	native, err := Load()
	if err != nil || native.ExecutionV2 {
		t.Fatalf("an unset variable must stay legacy for a native process: %+v %v", native, err)
	}
}

func TestDocumentedDockerSetupEnablesExecutionV2(t *testing.T) {
	root := filepath.Join("..", "..")
	example, err := os.ReadFile(filepath.Join(root, ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(example), "MIRAGE_EXECUTION_V2=true") {
		t.Fatal(".env.example must enable execution v2 so copying it does not force legacy mode")
	}
	if strings.Contains(string(example), "MIRAGE_EXECUTION_V2=false") {
		t.Fatal(".env.example still forces legacy execution")
	}
	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "${MIRAGE_EXECUTION_V2:-true}") {
		t.Fatal("compose must default execution v2 to true when the variable is unset")
	}
}
