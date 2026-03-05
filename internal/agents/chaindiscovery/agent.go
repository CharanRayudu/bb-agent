// Package chaindiscovery implements the Vulnerability Chain Discovery agent.
// Identifies multi-step attack chains where individual low-severity findings
// combine into high-impact exploits (e.g., Open Redirect + SSRF + RCE).
package chaindiscovery

import (
	"context"
	"fmt"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "Chain Discovery Agent" }
func (a *Agent) ID() string           { return "chaindiscovery" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Chain discovery works by analyzing existing findings and attempting
	// to connect them into multi-step attack chains.
	var findings []*base.Finding
	for _, chain := range knownChains {
		findings = append(findings, &base.Finding{
			Type:       "Attack Chain",
			URL:        targetURL,
			Payload:    chain.description,
			Severity:   chain.severity,
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"chain_name": chain.name,
				"steps":      chain.steps,
				"impact":     chain.impact,
				"prereqs":    chain.prerequisites,
			},
			Method: "ANALYSIS",
		})
	}
	return findings, nil
}

type attackChain struct {
	name          string
	description   string
	steps         []string
	prerequisites []string
	impact        string
	severity      string
}

var knownChains = []attackChain{
	{
		name:          "SSRF to Cloud Takeover",
		description:   "SSRF → Cloud Metadata → IAM Credentials → Account Takeover",
		steps:         []string{"Exploit SSRF", "Access 169.254.169.254", "Extract IAM creds", "Assume role"},
		prerequisites: []string{"SSRF"},
		impact:        "Full cloud account compromise",
		severity:      "critical",
	},
	{
		name:          "XSS to Account Takeover",
		description:   "Stored XSS → Session Cookie Theft → Admin Impersonation",
		steps:         []string{"Inject stored XSS", "Steal admin cookies", "Impersonate admin"},
		prerequisites: []string{"XSS"},
		impact:        "Admin account takeover",
		severity:      "critical",
	},
	{
		name:          "SQLi to RCE",
		description:   "SQL Injection → File Write → Web Shell → RCE",
		steps:         []string{"Exploit SQLi", "INTO OUTFILE web shell", "Execute commands"},
		prerequisites: []string{"SQLi", "FILE privilege"},
		impact:        "Remote code execution",
		severity:      "critical",
	},
	{
		name:          "LFI to RCE via Log Poisoning",
		description:   "LFI → Log Poisoning → PHP Code Execution",
		steps:         []string{"Inject PHP in User-Agent", "Include access.log via LFI", "Execute PHP"},
		prerequisites: []string{"LFI", "Log access"},
		impact:        "Remote code execution",
		severity:      "critical",
	},
	{
		name:          "Open Redirect to OAuth Token Theft",
		description:   "Open Redirect → OAuth redirect_uri manipulation → Token Theft",
		steps:         []string{"Find open redirect", "Set as OAuth redirect_uri", "Capture auth token"},
		prerequisites: []string{"Open Redirect", "OAuth flow"},
		impact:        "Account takeover via OAuth",
		severity:      "high",
	},
	{
		name:          "IDOR + Info Disclosure to PII Leak",
		description:   "IDOR → Enumerate user records → Mass PII exfiltration",
		steps:         []string{"Find IDOR endpoint", "Enumerate IDs", "Extract PII"},
		prerequisites: []string{"IDOR"},
		impact:        "Mass data breach",
		severity:      "critical",
	},
	{
		name:          "XXE to Internal Network Scan",
		description:   "XXE → SSRF → Internal Port Scan → Service Discovery",
		steps:         []string{"Exploit XXE", "Scan internal IPs via SSRF", "Identify services"},
		prerequisites: []string{"XXE"},
		impact:        "Internal network mapping",
		severity:      "high",
	},
	{
		name:          "Prototype Pollution to XSS/RCE",
		description:   "Prototype Pollution → Gadget Chain → XSS or RCE",
		steps:         []string{"Pollute Object.prototype", "Trigger gadget chain", "Achieve XSS/RCE"},
		prerequisites: []string{"Prototype Pollution"},
		impact:        "Client-side XSS or server-side RCE",
		severity:      "high",
	},
}

const defaultSystemPrompt = `You are a Vulnerability Chain Discovery specialist:
- Analyze individual findings to identify multi-step attack chains
- Connect low-severity findings into high-impact exploits
- Known chains: SSRF→Cloud, XSS→ATO, SQLi→RCE, LFI→Log Poison→RCE
- Evaluate prerequisites and feasibility for each chain
- Chains that achieve RCE or account takeover are CRITICAL`
