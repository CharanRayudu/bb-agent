package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/docker"
	"github.com/bb-agent/mirage/internal/llm"
)

// Tool represents an executable capability available to the agent
type Tool struct {
	Definition llm.ToolDefinition
	Execute    func(ctx context.Context, args json.RawMessage) (string, error)
}

// Registry holds all available tools
type Registry struct {
	tools   map[string]*Tool
	sandbox *docker.Sandbox
}

// NewRegistry creates a tool registry with all built-in tools
func NewRegistry(sandbox *docker.Sandbox) *Registry {
	r := &Registry{
		tools:   make(map[string]*Tool),
		sandbox: sandbox,
	}
	r.registerBuiltins()
	return r
}

func (r *Registry) registerBuiltins() {
	// execute_command — run a shell command in the Docker sandbox
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "execute_command",
			Description: "Execute a shell command inside a secure, sandboxed Docker container equipped with penetration testing tools (nmap, nikto, sqlmap, gobuster, nuclei, metasploit, curl, wget, dig, whois, netcat, python3, etc.). Use this to run security scans, network reconnaissance, exploitation attempts, and data collection. The command runs in an isolated environment with network access to the target.\n\nIMPORTANT LOCATIONS:\n- Wordlists for gobuster/dirb are located at: `/usr/share/dirb/wordlists/common.txt` and others in `/usr/share/dirb/wordlists/`. Do NOT assume `/usr/share/wordlists` exists.\n\nIMPORTANT: This container is PERSISTENT. If a tool you need is missing, you are encouraged to install it yourself using `apt-get update && apt-get install -y <tool>`. For open-source tools not in apt, you can freely use `git clone <repo>`, `go install <pkg>`, `pip install <pkg>`, or `wget` to download and compile them from source. Anything you install or payload you download will remain available for subsequent commands and future pentest scans.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "The shell command to execute (e.g., 'nmap -sV -sC target.com', 'sqlmap -u http://target.com/page?id=1 --batch')",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum execution time in seconds (default: 300, max: 600)",
					},
				},
				"required": []string{"command"},
			},
		},
		Execute: r.executeCommand,
	})

	// think — internal reasoning/planning step
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "think",
			Description: "Use this tool to think through a problem, plan your next steps, analyze results, or reason about findings. This does not execute anything — it's purely for structured thinking. Use this before making decisions about what tool to run next, or to analyze output from previous commands.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"thought": map[string]interface{}{
						"type":        "string",
						"description": "Your reasoning, analysis, or plan",
					},
				},
				"required": []string{"thought"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Thought string `json:"thought"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			return fmt.Sprintf("Thought recorded: %s", params.Thought), nil
		},
	})

	// report_findings — create a structured report
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "report_findings",
			Description: "Generate a structured findings report for a completed security assessment step. Use this after you have gathered and analyzed results from your testing. Include vulnerability details, severity ratings, and remediation suggestions.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Title of the finding or report section",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"critical", "high", "medium", "low", "info"},
						"description": "Severity level of the finding",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Detailed description of the finding, evidence collected, and potential impact",
					},
					"remediation": map[string]interface{}{
						"type":        "string",
						"description": "Suggested remediation steps",
					},
				},
				"required": []string{"title", "severity", "description"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Title       string `json:"title"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Remediation string `json:"remediation"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			report := fmt.Sprintf("## %s\n**Severity**: %s\n\n%s", params.Title, params.Severity, params.Description)
			if params.Remediation != "" {
				report += fmt.Sprintf("\n\n**Remediation**: %s", params.Remediation)
			}
			return report, nil
		},
	})

	// complete_task — signal that the current task is done
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "complete_task",
			Description: "Signal that you have completed the current penetration testing task. Provide a summary of what was accomplished, key findings, and any recommended next steps.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"summary": map[string]interface{}{
						"type":        "string",
						"description": "Summary of what was accomplished in this task",
					},
					"findings": map[string]interface{}{
						"type":        "string",
						"description": "Key security findings discovered",
					},
					"next_steps": map[string]interface{}{
						"type":        "string",
						"description": "Recommended next steps for further testing",
					},
				},
				"required": []string{"summary"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Summary   string `json:"summary"`
				Findings  string `json:"findings"`
				NextSteps string `json:"next_steps"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := fmt.Sprintf("Task completed.\n\nSummary: %s", params.Summary)
			if params.Findings != "" {
				result += fmt.Sprintf("\n\nFindings: %s", params.Findings)
			}
			return result, nil
		},
	})

	// execute_browser_script — native headless browser driver
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "execute_browser_script",
			Description: "Execute a custom Playwright (Node.js) script inside the headless browser environment to interact with SPAs, bypass captchas, extract DOM-based data, or login. Provide the raw javascript code. The script will be saved to a temporary file and run with `node`. Console output will be returned. Note: the `playwright` module is globally installed, so you can `require('playwright')`. Always make sure your scripts handle errors and clean up cleanly using `browser.close()`.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"script": map[string]interface{}{
						"type":        "string",
						"description": "The raw Javascript code using Playwright to run.",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum execution time in seconds (default: 60)",
					},
				},
				"required": []string{"script"},
			},
		},
		Execute: r.executeBrowserScript,
	})
}

// AddUpdateMemoryTool registers the memory tool with a callback to the orchestrator's state array
func (r *Registry) AddUpdateMemoryTool(onMemorySaved func(string)) {
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "update_memory",
			Description: "Save crucial discoveries (open ports, valid URLs, identified CVEs) to your permanent scratchpad so you don't forget them.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"discovery": map[string]interface{}{
						"type":        "string",
						"description": "Clear, concise summary of what you discovered (e.g. 'Port 80/443 open, running Nginx 1.18.0')",
					},
				},
				"required": []string{"discovery"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Discovery string `json:"discovery"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			onMemorySaved(params.Discovery)
			return fmt.Sprintf("[MEMORY SAVED]: %s", params.Discovery), nil
		},
	})
}

func (r *Registry) executeCommand(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid command args: %w", err)
	}

	if params.Timeout <= 0 {
		params.Timeout = 300
	}
	if params.Timeout > 600 {
		params.Timeout = 600
	}

	// Intercept and block unauthorized commands
	lowercaseCmd := strings.ToLower(params.Command)
	if strings.HasPrefix(lowercaseCmd, "nikto") || strings.Contains(lowercaseCmd, " nikto ") {
		return "[ERROR]: The 'nikto' scanner is explicitly prohibited by the user. Do not use this tool. Please rely on nuclei or manual enumeration instead.", nil
	}

	log.Printf("🔧 Executing: %s (timeout: %ds)", params.Command, params.Timeout)

	result, err := r.sandbox.Execute(ctx, params.Command, params.Timeout)
	if err != nil {
		return "", fmt.Errorf("sandbox execution failed: %w", err)
	}

	output := result.Stdout
	if result.Stderr != "" {
		output += "\n" + result.Stderr
	}
	output += fmt.Sprintf("\n\n[Exit Code: %d | Duration: %s]", result.ExitCode, result.Duration.Round(time.Millisecond))

	// Truncate very long output to avoid filling LLM context
	const maxOutput = 15000
	if len(output) > maxOutput {
		output = output[:maxOutput] + "\n\n... [output truncated, showing first 15000 characters]"
	}

	return output, nil
}

func (r *Registry) executeBrowserScript(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Script  string `json:"script"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid browser script args: %w", err)
	}

	if params.Timeout <= 0 {
		params.Timeout = 60
	}
	if params.Timeout > 300 {
		params.Timeout = 300
	}

	log.Printf("🌐 Executing Browser Script (timeout: %ds)", params.Timeout)

	// Base64 encode the script to avoid shell escaping issues
	encodedScript := base64.StdEncoding.EncodeToString([]byte(params.Script))

	// Decode script and execute with node
	cmd := fmt.Sprintf("echo %s | base64 -d > /tmp/browser_script.js && export NODE_PATH=/usr/lib/node_modules/ && node /tmp/browser_script.js", encodedScript)

	result, err := r.sandbox.Execute(ctx, cmd, params.Timeout)
	if err != nil {
		return "", fmt.Errorf("sandbox browser execution failed: %w", err)
	}

	output := result.Stdout
	if result.Stderr != "" {
		output += "\n" + result.Stderr
	}
	output += fmt.Sprintf("\n\n[Exit Code: %d | Duration: %s]", result.ExitCode, result.Duration.Round(time.Millisecond))

	// Truncate very long output
	const maxOutput = 20000
	if len(output) > maxOutput {
		output = output[:maxOutput] + "\n\n... [output truncated, showing first 20000 characters]"
	}

	return output, nil
}

// Register adds a tool to the registry
func (r *Registry) Register(tool *Tool) {
	r.tools[tool.Definition.Name] = tool
}

// Get returns a tool by name
func (r *Registry) Get(name string) (*Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Definitions returns all tool definitions for the LLM
func (r *Registry) Definitions() []llm.ToolDefinition {
	defs := make([]llm.ToolDefinition, 0, len(r.tools))
	for _, t := range r.tools {
		defs = append(defs, t.Definition)
	}
	return defs
}
