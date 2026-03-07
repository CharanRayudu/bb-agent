package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// AddPayloadMutationTool registers the LLM-powered payload generation tool
func (r *Registry) AddPayloadMutationTool(provider llm.Provider) {
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "generate_payloads",
			Description: "Use AI to generate context-aware, novel attack payloads based on the target's tech stack and detected WAF. This generates payloads that standard wordlists don't contain -- custom bypass techniques, encoding tricks, and framework-specific vectors.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"vuln_type": map[string]interface{}{
						"type":        "string",
						"description": "The vulnerability type to generate payloads for (e.g., 'XSS', 'SQLi', 'SSRF', 'SSTI', 'Command Injection', 'Path Traversal')",
					},
					"tech_stack": map[string]interface{}{
						"type":        "string",
						"description": "The detected technology stack (e.g., 'PHP 7.4, MySQL 5.7, Apache 2.4, Linux')",
					},
					"waf_detected": map[string]interface{}{
						"type":        "string",
						"description": "Any detected WAF/filtering (e.g., 'Cloudflare', 'ModSecurity', 'custom input filter blocking <script>', 'none detected')",
					},
					"context": map[string]interface{}{
						"type":        "string",
						"description": "Additional context about the injection point (e.g., 'GET parameter id in search form', 'POST body JSON field user.name', 'HTTP header X-Forwarded-For')",
					},
					"count": map[string]interface{}{
						"type":        "integer",
						"description": "Number of payloads to generate (default: 10, max: 25)",
					},
				},
				"required": []string{"vuln_type", "tech_stack"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				VulnType    string `json:"vuln_type"`
				TechStack   string `json:"tech_stack"`
				WAFDetected string `json:"waf_detected"`
				Context     string `json:"context"`
				Count       int    `json:"count"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid payload mutation args: %w", err)
			}

			if params.Count == 0 {
				params.Count = 10
			}
			if params.Count > 25 {
				params.Count = 25
			}
			if params.WAFDetected == "" {
				params.WAFDetected = "none detected"
			}

			mutationPrompt := fmt.Sprintf(`You are an elite security researcher and payload engineer. Generate %d novel, creative %s payloads.

TARGET ENVIRONMENT:
- Tech Stack: %s
- WAF/Filtering: %s
- Injection Context: %s

REQUIREMENTS:
1. Payloads MUST be designed to bypass the detected WAF/filters
2. Use encoding tricks (URL encoding, Unicode, HTML entities, double encoding)
3. Use framework-specific bypass techniques for the detected tech stack
4. Include at least 2 "polyglot" payloads that work across contexts
5. Vary payload length -- include both short probes and full exploitation payloads
6. Output ONLY a JSON array of strings, nothing else

Example output format: ["payload1", "payload2", ...]`,
				params.Count, params.VulnType, params.TechStack, params.WAFDetected, params.Context)

			resp, err := provider.Complete(ctx, llm.CompletionRequest{
				Messages: []models.ChatMessage{
					{Role: "user", Content: mutationPrompt},
				},
			})
			if err != nil {
				return "", fmt.Errorf("payload mutation LLM call failed: %w", err)
			}

			return fmt.Sprintf("[Payload Mutation Engine] Generated %d %s payloads for %s (WAF: %s):\n%s",
				params.Count, params.VulnType, params.TechStack, params.WAFDetected, resp.Content), nil
		},
	})
}
