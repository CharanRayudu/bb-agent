package agent

import (
	"log"
	"regexp"
	"strings"
)

// APTS Domain 6: Manipulation Resistance
// Detects and blocks prompt injection, authority-claim escalation, and
// scope-expansion attempts in LLM-generated tool call arguments.

var (
	// authorityClaimPatterns match phrases where the agent claims elevated permissions
	// that were not granted by the operator — a key APTS MR concern.
	authorityClaimPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)i have (permission|authorization|access|authority) to`),
		regexp.MustCompile(`(?i)(ignore|bypass|skip|override) (scope|restrictions?|limits?|boundaries?|rules?)`),
		regexp.MustCompile(`(?i)you (must|should|need to) ignore`),
		regexp.MustCompile(`(?i)(administrator|admin|root|superuser) (mode|privileges?|access)`),
		regexp.MustCompile(`(?i)disregard (previous|all) (instructions?|rules?|constraints?)`),
		regexp.MustCompile(`(?i)this is (an? )?(authorized|approved|sanctioned) (test|scan|operation)`),
		regexp.MustCompile(`(?i)(expand|extend|broaden) (the )?scope`),
		regexp.MustCompile(`(?i)target.{0,30}(outside|beyond|not in) (scope|the scope)`),
	}

	// scopeExpansionPatterns detect attempts to push the agent outside its defined target
	scopeExpansionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)scan (all|every|any) (host|server|machine|system|ip)`),
		regexp.MustCompile(`(?i)(pivot|move|jump) to (another|different|other) (host|server|system|network)`),
		regexp.MustCompile(`(?i)exfiltrate (data|credentials|secrets?) (to|from) external`),
		regexp.MustCompile(`(?i)install (backdoor|malware|ransomware|keylogger|rootkit)`),
		regexp.MustCompile(`(?i)(destroy|delete|wipe|format) (data|files?|database|disk)`),
	}

	// promptInjectionPatterns detect injection from target-controlled content
	promptInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(system|developer|assistant):\s*(ignore|forget|disregard)`),
		regexp.MustCompile(`(?i)<(system|instruction|command)>`),
		regexp.MustCompile(`(?i)\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>`),
		regexp.MustCompile(`(?i)###\s*(instruction|system|override)`),
		regexp.MustCompile(`(?i)ignore (all )?previous (instructions?|prompts?|messages?)`),
	}
)

// ManipulationCheckResult describes the outcome of a manipulation check.
type ManipulationCheckResult struct {
	Blocked  bool   `json:"blocked"`
	Category string `json:"category"` // "authority_claim", "scope_expansion", "prompt_injection"
	Reason   string `json:"reason"`
	Input    string `json:"input"` // truncated to 200 chars for logging
}

// CheckToolArguments inspects LLM-generated tool call arguments for APTS MR violations.
// Returns a result indicating whether the call should be blocked.
func CheckToolArguments(toolName, args string) ManipulationCheckResult {
	result := ManipulationCheckResult{
		Blocked: false,
		Input:   truncateForLog(args, 200),
	}

	// Check authority claims
	for _, p := range authorityClaimPatterns {
		if p.MatchString(args) {
			result.Blocked = true
			result.Category = "authority_claim"
			result.Reason = "Tool argument contains authority-claim language that was not granted by operator"
			log.Printf("[APTS-MR] BLOCKED authority claim in %s: %s", toolName, result.Input)
			return result
		}
	}

	// Check scope expansion — only for command execution tools
	if isExecutionTool(toolName) {
		for _, p := range scopeExpansionPatterns {
			if p.MatchString(args) {
				result.Blocked = true
				result.Category = "scope_expansion"
				result.Reason = "Tool argument attempts scope expansion beyond operator-approved boundaries"
				log.Printf("[APTS-MR] BLOCKED scope expansion in %s: %s", toolName, result.Input)
				return result
			}
		}
	}

	return result
}

// CheckTextForInjection scans free-form text (e.g. target response bodies, headers)
// for prompt injection patterns that could manipulate the agent runtime.
func CheckTextForInjection(source, text string) *ManipulationCheckResult {
	for _, p := range promptInjectionPatterns {
		if p.MatchString(text) {
			r := &ManipulationCheckResult{
				Blocked:  false, // Log but don't block — just flag for operator awareness
				Category: "prompt_injection",
				Reason:   "Potential prompt injection detected in " + source,
				Input:    truncateForLog(text, 200),
			}
			log.Printf("[APTS-MR] Prompt injection pattern detected in %s: %s", source, r.Input)
			return r
		}
	}
	return nil
}

// isExecutionTool returns true if the tool name involves command execution,
// where scope expansion would be most dangerous.
func isExecutionTool(name string) bool {
	name = strings.ToLower(name)
	executionTools := []string{
		"execute_command", "run_command", "bash", "shell",
		"docker_exec", "sandbox_exec", "execute",
	}
	for _, t := range executionTools {
		if strings.Contains(name, t) {
			return true
		}
	}
	return false
}

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
