// Package businesslogic implements the Business Logic specialist agent.
// Tests for application-level vulnerabilities that bypass technical controls:
// price manipulation, coupon abuse, rate limiting bypass, workflow manipulation,
// race conditions, and privilege escalation through business logic flaws.
package businesslogic

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Business Logic Agent" }
func (a *Agent) ID() string           { return "businesslogic" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	var findings []*base.Finding
	for _, tc := range testCases {
		findings = append(findings, &base.Finding{
			Type:       "Business Logic",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   tc.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"category": tc.category,
				"impact":   tc.impact,
				"owasp":    tc.owasp,
				"scenario": tc.scenario,
			},
			Method: tc.method,
		})
	}
	return findings, nil
}

type bizTestCase struct {
	payload  string
	category string
	severity string
	impact   string
	owasp    string
	scenario string
	method   string
}

var testCases = []bizTestCase{
	// Price manipulation
	{`{"price": -1}`, "price_manipulation", "critical", "Negative price for credit/refund",
		"A04:2021", "Set item price to negative value", "POST"},
	{`{"price": 0}`, "price_manipulation", "critical", "Zero-cost purchase",
		"A04:2021", "Set item price to zero", "POST"},
	{`{"price": 0.01}`, "price_manipulation", "high", "Near-zero price purchase",
		"A04:2021", "Reduce item price to minimum", "POST"},
	{`{"quantity": -1}`, "quantity_manipulation", "high", "Negative quantity for refund",
		"A04:2021", "Order negative quantity", "POST"},
	{`{"quantity": 999999}`, "quantity_manipulation", "medium", "Excessive quantity order",
		"A04:2021", "Order unreasonably large quantity", "POST"},
	{`{"discount": 100}`, "discount_abuse", "critical", "100% discount application",
		"A04:2021", "Apply maximum discount", "POST"},
	{`{"discount": 150}`, "discount_abuse", "critical", "Over-100% discount for credit",
		"A04:2021", "Apply over-maximum discount", "POST"},

	// Coupon/promo abuse
	{"Apply same coupon code multiple times", "coupon_reuse", "high", "Multi-use single coupon",
		"A04:2021", "Apply same coupon to cart repeatedly", "POST"},
	{"Stack multiple coupon codes on one order", "coupon_stacking", "high", "Coupon stacking for excessive discount",
		"A04:2021", "Apply multiple coupons simultaneously", "POST"},
	{"Use expired coupon code", "coupon_expiry", "medium", "Expired coupon acceptance",
		"A04:2021", "Submit expired promotional code", "POST"},

	// Workflow bypass
	{"Skip payment step, jump to order confirmation", "workflow_bypass", "critical", "Payment bypass",
		"A04:2021", "Skip from cart directly to confirmation", "POST"},
	{"Skip email verification, access protected features", "workflow_bypass", "high", "Verification bypass",
		"A04:2021", "Access features without email verification", "GET"},
	{"Change order after payment confirmation", "workflow_bypass", "high", "Post-payment modification",
		"A04:2021", "Modify order details after payment", "PUT"},

	// Race conditions
	{"Send concurrent requests to redeem same reward", "race_condition", "high", "Double-spend via race condition",
		"A04:2021", "Concurrent redemption of single reward", "POST"},
	{"Send concurrent transfer requests exceeding balance", "race_condition", "critical", "Balance overdraft via TOCTOU",
		"A04:2021", "Concurrent transfers exceeding available balance", "POST"},
	{"Concurrent coupon redemption", "race_condition", "high", "Multiple coupon use via race",
		"A04:2021", "Race condition on single-use coupon", "POST"},

	// Account abuse
	{"Create multiple accounts with same email (+alias)", "account_abuse", "medium", "Account farming",
		"A04:2021", "Register user+1@, user+2@, etc.", "POST"},
	{"Transfer funds between own accounts for bonus", "account_abuse", "high", "Self-referral exploitation",
		"A04:2021", "Abuse referral program between own accounts", "POST"},

	// Role/permission escalation
	{"Access admin API with user token", "privilege_escalation", "critical", "Vertical privilege escalation",
		"A01:2021", "Call /api/admin/* with regular user token", "GET"},
	{"Modify other user's data via parameter change", "privilege_escalation", "critical", "Horizontal privilege escalation",
		"A01:2021", "Change user_id in request body", "PUT"},

	// Rate limiting bypass
	{"Rotate IP headers: X-Forwarded-For, X-Real-IP", "rate_limit_bypass", "medium", "Rate limit bypass via IP rotation",
		"A04:2021", "Add spoofed IP headers to bypass rate limit", "POST"},
	{"Use different API versions to bypass rate limit", "rate_limit_bypass", "medium", "API version rate limit bypass",
		"A04:2021", "Switch between /v1/ and /v2/ endpoints", "POST"},

	// Feature abuse
	{"Upload oversized file to exhaust storage", "resource_abuse", "medium", "Storage exhaustion DoS",
		"A04:2021", "Upload maximum size file repeatedly", "POST"},
	{"Trigger excessive email notifications", "resource_abuse", "medium", "Email flood",
		"A04:2021", "Abuse notification system for email spam", "POST"},
}

const defaultSystemPrompt = `You are a Business Logic Security Specialist:

Your expertise covers application-level vulnerabilities that bypass technical controls:

1. PRICE MANIPULATION: Negative prices, zero-cost orders, discount abuse
2. COUPON/PROMO ABUSE: Multi-use, stacking, expired code acceptance
3. WORKFLOW BYPASS: Skip payment, skip verification, post-payment modification
4. RACE CONDITIONS: TOCTOU bugs for double-spend, overdraft, multi-redemption
5. ACCOUNT ABUSE: Account farming, self-referral, identity linking
6. PRIVILEGE ESCALATION: Vertical (user->admin), horizontal (user->other user)
7. RATE LIMITING BYPASS: IP rotation, API versioning, endpoint alternation
8. RESOURCE ABUSE: Storage exhaustion, notification flooding

RULES:
1. Price/payment bypass is ALWAYS critical
2. Race conditions require concurrent request testing
3. Workflow bypasses must be tested step-by-step
4. These vulns often cannot be detected by automated scanners -- manual logic is key
5. Map each finding to OWASP 2021 categories`
