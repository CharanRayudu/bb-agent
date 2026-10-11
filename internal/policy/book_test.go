package policy

import (
	"testing"
	"time"
)

func TestAuthorizeStartSharedByTriggers(t *testing.T) {
	book := NewBook()
	now := time.Now()
	if d := book.AuthorizeStart("http://example.com", now); d.Allowed || d.Code != CodeAuthorizationMissing {
		t.Fatalf("empty book: %+v", d)
	}
	auth, err := AuthorizationForTarget("flow-1", "http://example.com", AutonomyL3, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	book.Put(auth)
	if d := book.AuthorizeStart("http://example.com/app", now); !d.Allowed {
		t.Fatalf("exact host should match: %+v", d)
	}
	if d := book.AuthorizeStart("http://api.example.com", now); d.Allowed || d.Code != CodeOutOfScope {
		t.Fatalf("subdomain should be denied: %+v", d)
	}
	if d := book.AuthorizeStart("http://example.com:22", now); d.Allowed || d.Code != CodeOutOfScope {
		t.Fatalf("other port should be denied: %+v", d)
	}
	if d := book.AuthorizeStart("http://example.com", now.Add(48*time.Hour)); d.Allowed {
		t.Fatalf("expired authorization should not start a scan: %+v", d)
	}
}
