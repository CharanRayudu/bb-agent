// Package authdiscovery implements the Authentication Discovery specialist agent.
// Identifies authentication mechanisms, tests for bypasses, and checks for
// default credentials, session management flaws, and 2FA weaknesses.
package authdiscovery

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Auth Discovery Agent" }
func (a *Agent) ID() string           { return "authdiscovery" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, tc := range testCases {
		findings = append(findings, &base.Finding{
			Type:       "Auth",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"category": tc.category},
			Method:     tc.method,
		})
	}
	return findings, nil
}

type authTestCase struct {
	payload  string
	category string
	severity string
	method   string
}

var testCases = []authTestCase{
	// Default credentials
	{"admin:admin", "default_creds", "critical", "POST"},
	{"admin:password", "default_creds", "critical", "POST"},
	{"admin:123456", "default_creds", "critical", "POST"},
	{"root:root", "default_creds", "critical", "POST"},
	{"test:test", "default_creds", "high", "POST"},
	// Authentication bypass
	{"Access protected resource without auth header", "auth_bypass", "critical", "GET"},
	{"Send empty Bearer token: Authorization: Bearer ", "token_bypass", "critical", "GET"},
	{"Send 'null' token: Authorization: Bearer null", "null_token", "high", "GET"},
	// Session management
	{"Check Set-Cookie for Secure, HttpOnly, SameSite flags", "session_flags", "medium", "GET"},
	{"Check session fixation: reuse pre-auth session ID", "session_fixation", "high", "GET"},
	{"Check session invalidation after password change", "session_invalidation", "medium", "POST"},
	// Password policy
	{"Attempt registration with password '1'", "weak_password", "medium", "POST"},
	{"Check for username enumeration via login timing", "user_enum", "medium", "POST"},
	// 2FA
	{"Bypass 2FA by directly accessing post-auth endpoint", "2fa_bypass", "critical", "GET"},
	{"Bruteforce 4-digit OTP (0000-9999)", "2fa_bruteforce", "high", "POST"},
	// OAuth
	{"Manipulate redirect_uri in OAuth flow", "oauth_redirect", "high", "GET"},
	{"Test for open redirect in OAuth callback", "oauth_openredirect", "medium", "GET"},
}

const defaultSystemPrompt = `You are an Authentication Security specialist:
- Default credential testing (admin:admin, admin:password, etc.)
- Authentication bypass (missing auth, empty tokens, null tokens)
- Session management (cookie flags, fixation, invalidation)
- Password policy testing (weak passwords, enumeration)
- 2FA bypass (direct endpoint access, OTP brute-force)
- OAuth flow manipulation (redirect_uri, state parameter)

RULES:
1. Auth bypass is CRITICAL severity
2. Default credentials is CRITICAL severity
3. Weak session management is MEDIUM-HIGH severity
4. Always check both cookie-based and token-based auth`
