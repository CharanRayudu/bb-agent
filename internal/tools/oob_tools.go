package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bb-agent/mirage/internal/llm"
)

// OOBProvider defines the interface for the OOB Manager so we don't
// create a circular import with the agent package.
type OOBProvider interface {
	GenerateToken() string
	GenerateCallbackURL(token string) string
	GenerateDNSCallback(token string) string
	Register(token, scanID, vulnType, targetURL, parameter string)
	GeneratePayloads(token string) map[string]string
	PendingCount() int
	GetInteractionsAny(scanID string) interface{}
	Stats() map[string]interface{}
}

// AddOOBTools registers OOB (Out-of-Band) tools for blind vulnerability detection
func (r *Registry) AddOOBTools(oob OOBProvider) {
	// Tool 1: Generate OOB callback URL
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "oob_generate",
			Description: "Generate a unique Out-of-Band (OOB) callback URL for detecting blind vulnerabilities (SSRF, RCE, XXE, Blind XSS). Returns a callback URL and DNS hostname that you can embed in payloads. When the target server makes a request to this URL, it confirms the vulnerability is exploitable. Use this BEFORE sending a blind payload.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"scan_id": map[string]interface{}{
						"type":        "string",
						"description": "A unique identifier for this scan (e.g., flow ID or subtask ID)",
					},
					"vuln_type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"ssrf", "rce", "xxe", "blind_xss", "sqli_oob"},
						"description": "The type of blind vulnerability being tested",
					},
					"target_url": map[string]interface{}{
						"type":        "string",
						"description": "The target URL where the payload is being injected",
					},
					"parameter": map[string]interface{}{
						"type":        "string",
						"description": "The parameter being tested (e.g., 'url', 'file', 'host')",
					},
				},
				"required": []string{"scan_id", "vuln_type", "target_url"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				ScanID    string `json:"scan_id"`
				VulnType  string `json:"vuln_type"`
				TargetURL string `json:"target_url"`
				Parameter string `json:"parameter"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}

			token := oob.GenerateToken()
			callbackURL := oob.GenerateCallbackURL(token)
			dnsCallback := oob.GenerateDNSCallback(token)

			// Register the token
			oob.Register(token, params.ScanID, params.VulnType, params.TargetURL, params.Parameter)

			// Generate payload variants
			payloads := oob.GeneratePayloads(token)

			result := fmt.Sprintf("🎯 OOB Token Generated\n\nCallback URL: %s\nDNS Hostname: %s\nToken: %s\n\n", callbackURL, dnsCallback, token)
			result += "Ready-to-use payloads:\n"
			for name, payload := range payloads {
				result += fmt.Sprintf("  %s: %s\n", name, payload)
			}
			result += fmt.Sprintf("\nPending tokens: %d", oob.PendingCount())

			return result, nil
		},
	})

	// Tool 2: Check for OOB callbacks
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "oob_poll",
			Description: "Check if an Out-of-Band (OOB) callback has been received for any registered tokens. Call this AFTER sending a blind payload to see if the target server made a request to our callback URL. A positive result CONFIRMS the vulnerability is exploitable.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"scan_id": map[string]interface{}{
						"type":        "string",
						"description": "The scan ID used when generating the OOB token",
					},
				},
				"required": []string{"scan_id"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				ScanID string `json:"scan_id"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}

			interactions := oob.GetInteractionsAny(params.ScanID)
			stats := oob.Stats()

			result, _ := json.MarshalIndent(map[string]interface{}{
				"interactions":   interactions,
				"pending_tokens": stats["pending_tokens"],
				"total_hits":     stats["total_interactions"],
			}, "", "  ")

			return string(result), nil
		},
	})
}
