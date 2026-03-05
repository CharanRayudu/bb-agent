// Package idor implements the Insecure Direct Object Reference specialist agent.
package idor

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "IDOR Agent" }
func (a *Agent) ID() string           { return "idor" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	testCases := generateTestCases(vulnContext)
	var findings []*base.Finding
	for _, tc := range testCases {
		findings = append(findings, &base.Finding{
			Type:       "IDOR",
			URL:        targetURL,
			Payload:    tc.payload,
			Severity:   mapSeverity(priority),
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"technique":    tc.technique,
				"param_type":   tc.paramType,
				"access_level": tc.accessLevel,
			},
			Method: tc.method,
		})
	}
	return findings, nil
}

type idorTestCase struct {
	payload     string
	technique   string
	paramType   string
	accessLevel string
	method      string
}

func generateTestCases(vulnCtx string) []idorTestCase {
	ctx := strings.ToLower(vulnCtx)
	var tests []idorTestCase

	// Sequential ID manipulation
	tests = append(tests,
		idorTestCase{"1", "sequential_id", "integer", "horizontal", "GET"},
		idorTestCase{"2", "sequential_id", "integer", "horizontal", "GET"},
		idorTestCase{"0", "boundary_id", "integer", "vertical", "GET"},
		idorTestCase{"-1", "negative_id", "integer", "boundary", "GET"},
		idorTestCase{"999999", "high_id", "integer", "boundary", "GET"},
	)

	// UUID manipulation
	if strings.Contains(ctx, "uuid") || strings.Contains(ctx, "guid") {
		tests = append(tests,
			idorTestCase{"00000000-0000-0000-0000-000000000000", "null_uuid", "uuid", "boundary", "GET"},
			idorTestCase{"00000000-0000-0000-0000-000000000001", "sequential_uuid", "uuid", "horizontal", "GET"},
		)
	}

	// HTTP method switching
	tests = append(tests,
		idorTestCase{"1", "method_switch_put", "integer", "vertical", "PUT"},
		idorTestCase{"1", "method_switch_delete", "integer", "vertical", "DELETE"},
		idorTestCase{"1", "method_switch_patch", "integer", "vertical", "PATCH"},
	)

	// Parameter pollution
	tests = append(tests,
		idorTestCase{"1&user_id=2", "param_pollution", "integer", "horizontal", "GET"},
	)

	// Array wrapping
	if strings.Contains(ctx, "json") || strings.Contains(ctx, "api") {
		tests = append(tests,
			idorTestCase{`{"id": [1, 2]}`, "array_wrap", "json", "horizontal", "POST"},
			idorTestCase{`{"id": "1", "role": "admin"}`, "mass_assignment", "json", "vertical", "POST"},
		)
	}

	return tests
}

func mapSeverity(p string) string {
	switch strings.ToLower(p) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return "high" // IDOR is typically high severity
	}
}

const defaultSystemPrompt = `You are an elite IDOR (Insecure Direct Object Reference) specialist with expertise in:
- Sequential/predictable ID enumeration
- UUID/GUID manipulation and boundary testing
- Horizontal privilege escalation (accessing other users' data)
- Vertical privilege escalation (accessing admin resources)
- HTTP method switching (GET→PUT/DELETE/PATCH)
- Parameter pollution and JSON array wrapping

RULES:
1. IDOR with data access is HIGH severity
2. IDOR with admin escalation is CRITICAL severity
3. Test both sequential IDs and boundary values (0, -1, max)
4. Try HTTP method switching for state-changing operations
5. Check for mass assignment via extra JSON fields
6. Compare response sizes/content between original and modified IDs`
