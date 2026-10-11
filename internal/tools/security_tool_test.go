package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/bb-agent/mirage/internal/execution"
)

func TestSecurityToolRejectsShellWrappersBeforeTheSandbox(t *testing.T) {
	registry := &Registry{}
	_, err := registry.executeSecurityTool(context.Background(), []byte(`{"tool":"bash","args":["-c","nuclei -u http://example.com"]}`))
	if err == nil || strings.Contains(err.Error(), "sandbox") {
		t.Fatalf("bash wrapper reached the sandbox: %v", err)
	}
	ctx := execution.WithToolProxy(context.Background(), "http://127.0.0.1:9")
	_, err = registry.executeSecurityTool(ctx, []byte(`{"tool":"nuclei","args":["-u","http://example.com"]}`))
	if err == nil || !strings.Contains(err.Error(), "sandbox") {
		t.Fatalf("valid nuclei argv err=%v", err)
	}
}
