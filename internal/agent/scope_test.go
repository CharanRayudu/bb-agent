package agent

import (
	"encoding/json"
	"testing"
)

func TestValidateToolArgsDoesNotScopeCheckCompleteTaskSummary(t *testing.T) {
	scope := NewScopeEngine("http://example.com")

	ok, reason := scope.ValidateToolArgs("complete_task", json.RawMessage(`{"summary":"BeautifulSoup mentioned http://evil.com in a report"}`))
	if !ok {
		t.Fatalf("expected complete_task to bypass scope validation, got blocked: %s", reason)
	}
}

func TestValidateToolArgsChecksExecuteCommandCommandField(t *testing.T) {
	scope := NewScopeEngine("http://example.com")

	ok, _ := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://example.com/login"}`))
	if !ok {
		t.Fatal("expected in-scope command to pass validation")
	}

	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://evil.com"}`))
	if ok {
		t.Fatal("expected out-of-scope command to be blocked")
	}
	if reason == "" {
		t.Fatal("expected block reason for out-of-scope command")
	}
}

func TestValidateToolArgsAllowsRootRelativeApplicationPaths(t *testing.T) {
	scope := NewScopeEngine("http://example.com")

	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s /login.php"}`))
	if !ok {
		t.Fatalf("expected root-relative app path to resolve in scope, got blocked: %s", reason)
	}
}

func TestValidateToolArgsIgnoresLocalTempArtifacts(t *testing.T) {
	scope := NewScopeEngine("http://example.com")

	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://example.com -c /tmp/dvwa.cookie"}`))
	if !ok {
		t.Fatalf("expected local temp artifact path to bypass scope checks, got blocked: %s", reason)
	}
}
