package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/policy"
)

func TestTriggeredScansShareAuthorizationCheck(t *testing.T) {
	s := New(&config.Config{ExecutionV2: true, OpenAIModel: "gpt-4o"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/cicd/trigger", bytes.NewBufferString(`{"target":"http://example.com","profile":"quick"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("CI status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(s.execLog.Decisions()) == 0 {
		t.Fatal("CI denial was not recorded")
	}
	if err := s.authorizeTriggeredScan("http://example.com", "schedule"); err == nil {
		t.Fatal("scheduled scan skipped the authorization check")
	}

	auth, err := policy.AuthorizationForTarget("flow-1", "http://example.com", policy.AutonomyL3, "operator", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.engagements.Put(auth)
	if err := s.authorizeTriggeredScan("http://example.com/app", "schedule"); err != nil {
		t.Fatal(err)
	}
	if err := s.authorizeTriggeredScan("http://example.com/app", "cicd"); err != nil {
		t.Fatal(err)
	}
	if err := s.authorizeTriggeredScan("http://other.example", "cicd"); err == nil {
		t.Fatal("unrelated target was authorized")
	}
}
