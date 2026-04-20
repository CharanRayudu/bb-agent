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

func TestPortStrictScope_AllowsCorrectPort(t *testing.T) {
	scope := NewScopeEngine("http://86.48.30.37:3001")
	if scope.AllowedPort != 3001 {
		t.Fatalf("expected AllowedPort=3001, got %d", scope.AllowedPort)
	}

	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://86.48.30.37:3001/api/products"}`))
	if !ok {
		t.Fatalf("expected correct-port request to pass, got blocked: %s", reason)
	}
}

func TestPortStrictScope_BlocksWrongPort(t *testing.T) {
	scope := NewScopeEngine("http://86.48.30.37:3001")

	ok, _ := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://86.48.30.37:22"}`))
	if ok {
		t.Fatal("expected wrong-port request (SSH) to be blocked")
	}
}

func TestPortStrictScope_BlocksDefaultPortWhenTargetHasCustomPort(t *testing.T) {
	scope := NewScopeEngine("http://86.48.30.37:3001")

	// curl http://86.48.30.37 with no port → effective port 80, not 3001
	ok, _ := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://86.48.30.37/etc/passwd"}`))
	if ok {
		t.Fatal("expected no-port request (port 80) to be blocked when target port is 3001")
	}
}

func TestNoPortScope_AllowsAnyPort(t *testing.T) {
	scope := NewScopeEngine("http://example.com")
	if scope.AllowedPort != 0 {
		t.Fatalf("expected AllowedPort=0 for target with no explicit port, got %d", scope.AllowedPort)
	}

	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"curl -s http://example.com:8080/api"}`))
	if !ok {
		t.Fatalf("expected any-port to be allowed when target has no port, got blocked: %s", reason)
	}
}

func TestShellVariableNotScopeBlocked(t *testing.T) {
	scope := NewScopeEngine("http://86.48.30.37:3001")

	// Shell variable like http://86.48.30.37:3001$p must NOT be treated as an OOS target
	ok, reason := scope.ValidateToolArgs("execute_command", json.RawMessage(`{"command":"for p in /api/products /rest/user; do curl http://86.48.30.37:3001$p; done"}`))
	if !ok {
		t.Fatalf("expected shell-variable URL to be filtered (not blocked as OOS), got: %s", reason)
	}
}
