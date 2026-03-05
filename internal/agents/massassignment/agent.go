// Package massassignment implements the Mass Assignment specialist agent.
// Tests for unprotected parameter binding where attackers can modify
// fields they shouldn't have access to (role, is_admin, price, etc.).
package massassignment

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Mass Assignment Agent" }
func (a *Agent) ID() string           { return "massassignment" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, tc := range testCases {
		findings = append(findings, &base.Finding{
			Type:       "Mass Assignment",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence:   map[string]interface{}{"field": tc.field, "impact": tc.impact},
			Method:     "POST",
		})
	}
	return findings, nil
}

type maTestCase struct {
	payload  string
	field    string
	impact   string
	severity string
}

var testCases = []maTestCase{
	// Privilege escalation
	{`{"role":"admin"}`, "role", "privilege_escalation", "critical"},
	{`{"is_admin":true}`, "is_admin", "privilege_escalation", "critical"},
	{`{"user_type":"administrator"}`, "user_type", "privilege_escalation", "critical"},
	{`{"permissions":["read","write","admin"]}`, "permissions", "privilege_escalation", "critical"},
	// Account manipulation
	{`{"verified":true}`, "verified", "account_manipulation", "high"},
	{`{"email_verified":true}`, "email_verified", "account_manipulation", "high"},
	{`{"active":true}`, "active", "account_manipulation", "medium"},
	// Financial manipulation
	{`{"price":0}`, "price", "financial_manipulation", "critical"},
	{`{"discount":100}`, "discount", "financial_manipulation", "critical"},
	{`{"balance":999999}`, "balance", "financial_manipulation", "critical"},
	// Ownership manipulation
	{`{"user_id":1}`, "user_id", "ownership_change", "high"},
	{`{"owner_id":1}`, "owner_id", "ownership_change", "high"},
	{`{"created_by":"admin"}`, "created_by", "ownership_change", "high"},
	// Internal fields
	{`{"id":1}`, "id", "internal_field", "medium"},
	{`{"created_at":"2020-01-01"}`, "created_at", "internal_field", "low"},
	{`{"updated_at":"2020-01-01"}`, "updated_at", "internal_field", "low"},
}

const defaultSystemPrompt = `You are a Mass Assignment specialist:
- Test for unprotected parameter binding (role, is_admin, permissions)
- Test financial fields (price, discount, balance)
- Test ownership fields (user_id, owner_id)
- Test internal fields (id, created_at, timestamps)
- Compare response before/after to confirm assignment worked

RULES:
1. Privilege escalation via mass assignment is CRITICAL
2. Financial manipulation is CRITICAL
3. Internal field modification is MEDIUM-LOW
4. Always check both PUT and PATCH methods`
