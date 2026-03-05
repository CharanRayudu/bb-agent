package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// ToolErrorStrategy defines how to recover from a specific tool failure
type ToolErrorStrategy struct {
	ShouldRetry bool
	NewArgs     string // Modified arguments for retry
	Delay       time.Duration
	Message     string // Human-readable explanation of the fix
}

// RetryWithBackoff executes a function with exponential backoff retry logic
func RetryWithBackoff(ctx context.Context, maxRetries int, baseDelay time.Duration, fn func() (string, error)) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err

		if attempt < maxRetries {
			delay := baseDelay * time.Duration(1<<uint(attempt)) // exponential: 2s, 4s, 8s
			log.Printf("[resilience] Attempt %d/%d failed: %v. Retrying in %v...", attempt+1, maxRetries, err, delay)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
	return "", fmt.Errorf("all %d retries exhausted: %w", maxRetries, lastErr)
}

// HealToolError analyzes a tool execution error and returns a recovery strategy
func HealToolError(toolName string, output string, originalArgs json.RawMessage) ToolErrorStrategy {
	outputLower := strings.ToLower(output)

	// Pattern 1: Connection refused / host unreachable
	if strings.Contains(outputLower, "connection refused") ||
		strings.Contains(outputLower, "no route to host") ||
		strings.Contains(outputLower, "host unreachable") {
		return ToolErrorStrategy{
			ShouldRetry: true,
			Delay:       5 * time.Second,
			Message:     "🔧 Target connection failed. Waiting 5s before retry (network may be intermittent).",
		}
	}

	// Pattern 2: Timeout
	if strings.Contains(outputLower, "timeout") ||
		strings.Contains(outputLower, "timed out") ||
		strings.Contains(outputLower, "context deadline exceeded") {
		return ToolErrorStrategy{
			ShouldRetry: true,
			NewArgs:     injectTimeoutFlag(originalArgs),
			Delay:       2 * time.Second,
			Message:     "🔧 Command timed out. Retrying with reduced scope/timeout.",
		}
	}

	// Pattern 3: OOM Kill (exit code 137)
	if strings.Contains(output, "Exit Code: 137") ||
		strings.Contains(outputLower, "killed") ||
		strings.Contains(outputLower, "out of memory") {
		return ToolErrorStrategy{
			ShouldRetry: true,
			NewArgs:     injectConcurrencyLimit(originalArgs),
			Delay:       3 * time.Second,
			Message:     "🔧 Process killed (OOM). Retrying with lower concurrency.",
		}
	}

	// Pattern 4: Command not found → Dynamic tool install
	if strings.Contains(outputLower, "command not found") ||
		strings.Contains(outputLower, "not found") && strings.Contains(outputLower, "no such file") {
		toolToInstall := extractMissingTool(output)
		if toolToInstall != "" {
			installCmd := GetInstallCommand(toolToInstall)
			if installCmd != "" {
				return ToolErrorStrategy{
					ShouldRetry: true,
					NewArgs:     buildInstallAndRetryArgs(installCmd, originalArgs),
					Delay:       1 * time.Second,
					Message:     fmt.Sprintf("🔧 Tool '%s' not found. Auto-installing and retrying.", toolToInstall),
				}
			}
		}
		return ToolErrorStrategy{
			ShouldRetry: false,
			Message:     fmt.Sprintf("❌ Command not found and no auto-install available: %s", output),
		}
	}

	// Pattern 5: Rate limiting / WAF block
	if strings.Contains(outputLower, "429") ||
		strings.Contains(outputLower, "rate limit") ||
		strings.Contains(outputLower, "too many requests") ||
		strings.Contains(outputLower, "access denied") {
		return ToolErrorStrategy{
			ShouldRetry: true,
			NewArgs:     injectRateLimit(originalArgs),
			Delay:       10 * time.Second,
			Message:     "🔧 Rate limited by target/WAF. Backing off 10s and reducing scan rate.",
		}
	}

	// Pattern 6: SSL/TLS errors
	if strings.Contains(outputLower, "certificate") ||
		strings.Contains(outputLower, "ssl") && strings.Contains(outputLower, "error") ||
		strings.Contains(outputLower, "tls handshake") {
		return ToolErrorStrategy{
			ShouldRetry: true,
			NewArgs:     injectInsecureFlag(originalArgs),
			Delay:       1 * time.Second,
			Message:     "🔧 SSL/TLS error. Retrying with --insecure flag.",
		}
	}

	// No known recovery pattern
	return ToolErrorStrategy{
		ShouldRetry: false,
		Message:     "No automatic recovery available for this error.",
	}
}

// ExecuteWithHealing wraps tool execution with self-healing retry logic
func ExecuteWithHealing(ctx context.Context, toolName string, execFn func(json.RawMessage) (string, error), args json.RawMessage, emitWarning func(string)) (string, error) {
	const maxHealAttempts = 3

	currentArgs := args
	for attempt := 0; attempt < maxHealAttempts; attempt++ {
		result, err := execFn(currentArgs)

		// Check if result indicates an error even if err is nil (tool returned error in output)
		if err == nil && !isErrorOutput(result) {
			return result, nil
		}

		errorOutput := result
		if err != nil {
			errorOutput = err.Error()
		}

		strategy := HealToolError(toolName, errorOutput, currentArgs)

		if !strategy.ShouldRetry {
			if emitWarning != nil {
				emitWarning(fmt.Sprintf("❌ [Self-Heal Failed] %s: %s", toolName, strategy.Message))
			}
			if err != nil {
				return "", err
			}
			return result, nil
		}

		if emitWarning != nil {
			emitWarning(fmt.Sprintf("🔄 [Self-Heal Attempt %d/%d] %s", attempt+1, maxHealAttempts, strategy.Message))
		}

		// Apply recovery strategy
		if strategy.NewArgs != "" {
			currentArgs = json.RawMessage(strategy.NewArgs)
		}

		select {
		case <-time.After(strategy.Delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	return "", fmt.Errorf("self-healing exhausted after %d attempts for tool %s", maxHealAttempts, toolName)
}

// --- Helper functions for argument manipulation ---

func injectTimeoutFlag(args json.RawMessage) string {
	var params map[string]interface{}
	json.Unmarshal(args, &params)
	if cmd, ok := params["command"].(string); ok {
		// Reduce timeout for common tools
		if strings.Contains(cmd, "nuclei") && !strings.Contains(cmd, "-timeout") {
			params["command"] = cmd + " -timeout 15"
		} else if strings.Contains(cmd, "ffuf") && !strings.Contains(cmd, "-timeout") {
			params["command"] = cmd + " -timeout 10"
		}
		if t, ok := params["timeout"].(float64); ok && t > 120 {
			params["timeout"] = t / 2 // Halve the timeout
		}
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func injectConcurrencyLimit(args json.RawMessage) string {
	var params map[string]interface{}
	json.Unmarshal(args, &params)
	if cmd, ok := params["command"].(string); ok {
		if strings.Contains(cmd, "nuclei") {
			params["command"] = cmd + " -c 2 -rl 5"
		} else if strings.Contains(cmd, "ffuf") {
			params["command"] = cmd + " -t 5 -rate 5"
		} else if strings.Contains(cmd, "sqlmap") {
			params["command"] = cmd + " --threads=1"
		}
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func injectRateLimit(args json.RawMessage) string {
	var params map[string]interface{}
	json.Unmarshal(args, &params)
	if cmd, ok := params["command"].(string); ok {
		if strings.Contains(cmd, "nuclei") {
			params["command"] = cmd + " -rl 2"
		} else if strings.Contains(cmd, "ffuf") {
			params["command"] = cmd + " -rate 2"
		} else if strings.Contains(cmd, "gobuster") || strings.Contains(cmd, "feroxbuster") {
			params["command"] = cmd + " --delay 2s"
		}
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func injectInsecureFlag(args json.RawMessage) string {
	var params map[string]interface{}
	json.Unmarshal(args, &params)
	if cmd, ok := params["command"].(string); ok {
		if strings.Contains(cmd, "curl") && !strings.Contains(cmd, "-k") {
			params["command"] = cmd + " -k"
		} else if strings.Contains(cmd, "nuclei") {
			params["command"] = cmd + " -tls-impersonate"
		} else if strings.Contains(cmd, "ffuf") {
			// ffuf doesn't have insecure flag, skip TLS verification via env
			params["command"] = "GODEBUG=x509ignoreCN=0 " + cmd
		}
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func extractMissingTool(errOutput string) string {
	// Pattern: "bash: feroxbuster: command not found"
	parts := strings.Split(errOutput, ":")
	for i, p := range parts {
		if strings.Contains(strings.ToLower(p), "command not found") && i > 0 {
			return strings.TrimSpace(parts[i-1])
		}
	}
	return ""
}

func buildInstallAndRetryArgs(installCmd string, originalArgs json.RawMessage) string {
	var params map[string]interface{}
	json.Unmarshal(originalArgs, &params)
	if cmd, ok := params["command"].(string); ok {
		params["command"] = installCmd + " && " + cmd
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func isErrorOutput(output string) bool {
	lower := strings.ToLower(output)
	errorIndicators := []string{
		"exit code: 1",
		"exit code: 2",
		"exit code: 137",
		"fatal error",
		"panic:",
		"segmentation fault",
	}
	for _, indicator := range errorIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// GetInstallCommand returns the install command for a known security tool
func GetInstallCommand(toolName string) string {
	installs := map[string]string{
		"feroxbuster": "apt-get update -qq && apt-get install -y -qq feroxbuster 2>/dev/null || cargo install feroxbuster 2>/dev/null",
		"xsstrike":    "pip3 install xsstrike 2>/dev/null",
		"dirsearch":   "pip3 install dirsearch 2>/dev/null",
		"subfinder":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null",
		"httpx":       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null",
		"katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null",
		"interactsh":  "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null",
		"gau":         "go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null",
		"waybackurls": "go install github.com/tomnomnom/waybackurls@latest 2>/dev/null",
		"arjun":       "pip3 install arjun 2>/dev/null",
		"paramspider": "pip3 install paramspider 2>/dev/null",
		"wfuzz":       "pip3 install wfuzz 2>/dev/null",
		"jwt_tool":    "pip3 install jwt_tool 2>/dev/null",
		"trufflehog":  "pip3 install trufflehog 2>/dev/null",
		"rustscan":    "apt-get update -qq && apt-get install -y -qq rustscan 2>/dev/null",
		"amass":       "go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null",
	}
	return installs[strings.ToLower(toolName)]
}
