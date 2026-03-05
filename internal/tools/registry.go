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
						"description": "Maximum execution time in seconds (default: 300, max: 1800)",
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

	// analyze_source_code — CodeMapper for finding injection choke points
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "analyze_source_code",
			Description: "Clone a git repository or download source code and analyze it for security-critical patterns (injection points, unsafe calls, hardcoded secrets, auth bypasses). Uses grep/semgrep patterns to find 'choke points' — code locations most likely to contain vulnerabilities. Returns a structured list of findings with file paths, line numbers, and matched patterns.\n\nUse this BEFORE fuzzing to identify exactly which parameters, endpoints, and functions to target.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Git repository URL or raw file URL to analyze (e.g., 'https://github.com/org/repo')",
					},
					"focus": map[string]interface{}{
						"type":        "string",
						"description": "What to look for: 'sqli' (SQL injection), 'xss' (cross-site scripting), 'cmdi' (command injection), 'ssrf' (server-side request forgery), 'auth' (authentication bypass), 'secrets' (hardcoded keys/passwords), or 'all'",
					},
					"path_filter": map[string]interface{}{
						"type":        "string",
						"description": "Optional: only analyze files matching this glob pattern (e.g., '*.js', 'src/**/*.py')",
					},
				},
				"required": []string{"url", "focus"},
			},
		},
		Execute: r.analyzeSourceCode,
	})
}

// AddUpdateBrainTool registers the Mirage 2.0 structured brain tool
func (r *Registry) AddUpdateBrainTool(onBrainUpdate func(string, string)) {
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "update_brain",
			Description: "CRITICAL: Save crucial discoveries to your long-term memory. Categorize them accurately to help the Mastermind Orchestrator plan the next steps.",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"category": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"lead", "finding", "exclusion", "credentials", "pivot", "tech"},
						"description": "'lead': interesting paths/params to investigate; 'finding': confirmed vulnerability; 'exclusion': dead end or blocked path; 'credentials': discovered valid credentials, session cookies, or JWT tokens; 'pivot': ANY discovery that unlocks a new attack surface; 'tech': discovered technology stack (e.g., 'PHP 8.1, MySQL, Cloudflare').",
					},
					"discovery": map[string]interface{}{
						"type":        "string",
						"description": "Clear summary of the discovery (e.g. 'SQLi confirmed on /api/user?id=1' or 'Port 8443 is filtering traffic').",
					},
				},
				"required": []string{"category", "discovery"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Category  string `json:"category"`
				Discovery string `json:"discovery"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			onBrainUpdate(params.Category, params.Discovery)
			return fmt.Sprintf("[BRAIN UPDATED (%s)]: %s", params.Category, params.Discovery), nil
		},
	})
}

// AddVisualCrawlTool registers the headless browser discovery tool
func (r *Registry) AddVisualCrawlTool(onCrawl func(context.Context, string) (string, error)) {
	r.Register(&Tool{
		Definition: llm.ToolDefinition{
			Name:        "visual_crawl",
			Description: "CRITICAL for SPAs: Use a headless browser to discover dynamic links and inputs that static crawlers miss. Use this if the target uses a modern JS framework (React, Vue, Angular) or has a hash-based router (/#/).",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The URL to crawl (must be the entry point of the SPA)",
					},
				},
				"required": []string{"url"},
			},
		},
		Execute: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			return onCrawl(ctx, params.URL)
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
	if params.Timeout > 1800 {
		params.Timeout = 1800
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

func (r *Registry) analyzeSourceCode(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		URL        string `json:"url"`
		Focus      string `json:"focus"`
		PathFilter string `json:"path_filter"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid analyze_source_code args: %w", err)
	}

	log.Printf("🔍 CodeMapper: Analyzing %s (focus: %s)", params.URL, params.Focus)

	// Build the analysis script
	cloneCmd := fmt.Sprintf("cd /tmp && rm -rf codemapper_repo && git clone --depth=1 %s codemapper_repo 2>&1 && cd codemapper_repo", params.URL)

	// Build grep patterns based on focus area
	var grepPatterns string
	switch strings.ToLower(params.Focus) {
	case "sqli":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.java' --include='*.go' --include='*.rb' --include='*.ts' -E "(query\(|execute\(|raw\(|exec\(|\.query|sql\.|SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM|WHERE.*=.*\+|db\.|cursor\.|prepare\()" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	case "xss":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.html' --include='*.jsx' --include='*.ts' --include='*.tsx' -E "(innerHTML|outerHTML|document\.write|\.html\(|v-html|dangerouslySetInnerHTML|res\.send\(|render\(|\.safe|mark_safe)" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	case "cmdi":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.java' --include='*.go' --include='*.rb' -E "(exec\(|system\(|popen\(|spawn\(|execSync|child_process|subprocess|os\.system|os\.popen|Runtime\.getRuntime|ProcessBuilder)" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	case "ssrf":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.java' --include='*.go' -E "(fetch\(|axios\.|requests\.(get|post|put)|http\.Get|urllib|curl_exec|file_get_contents|HttpClient|RestTemplate)" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	case "auth":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.java' --include='*.go' -E "(password|secret|token|api.?key|jwt|bearer|auth|login|session|cookie|hash|bcrypt|sha256|md5|verify|authenticate|authorize)" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	case "secrets":
		grepPatterns = `grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.java' --include='*.go' --include='*.env' --include='*.yml' --include='*.yaml' --include='*.json' -E "(API_KEY|SECRET_KEY|PRIVATE_KEY|password\s*=|secret\s*=|token\s*=|aws_access)" /tmp/codemapper_repo/ 2>/dev/null | head -80`
	default: // "all"
		grepPatterns = `echo "=== SQL Injection ===" && grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.go' -E "(query\(|execute\(|raw\(|\.query|SELECT.*FROM)" /tmp/codemapper_repo/ 2>/dev/null | head -30 && echo "=== XSS ===" && grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.html' -E "(innerHTML|document\.write|\.html\(|dangerouslySetInnerHTML)" /tmp/codemapper_repo/ 2>/dev/null | head -30 && echo "=== Command Injection ===" && grep -rn --include='*.js' --include='*.py' --include='*.php' --include='*.go' -E "(exec\(|system\(|popen\(|spawn\(|subprocess)" /tmp/codemapper_repo/ 2>/dev/null | head -30 && echo "=== Secrets ===" && grep -rn -E "(API_KEY|SECRET_KEY|password\s*=|token\s*=)" /tmp/codemapper_repo/ 2>/dev/null | head -20`
	}

	// Apply path filter if provided
	if params.PathFilter != "" {
		grepPatterns = strings.ReplaceAll(grepPatterns, "/tmp/codemapper_repo/", fmt.Sprintf("/tmp/codemapper_repo/%s", params.PathFilter))
	}

	// Get repo stats
	statsCmd := `echo "=== Repo Stats ===" && find /tmp/codemapper_repo -type f \( -name '*.js' -o -name '*.py' -o -name '*.php' -o -name '*.go' -o -name '*.java' -o -name '*.rb' -o -name '*.ts' \) 2>/dev/null | wc -l && echo " source files found" && echo "=== Directory Structure ===" && find /tmp/codemapper_repo -type d -maxdepth 3 2>/dev/null | head -30`

	fullCmd := fmt.Sprintf("%s && %s && echo '=== Security Analysis ===' && %s", cloneCmd, statsCmd, grepPatterns)

	result, err := r.sandbox.Execute(ctx, fullCmd, 120)
	if err != nil {
		return "", fmt.Errorf("codemapper execution failed: %w", err)
	}

	output := result.Stdout
	if result.Stderr != "" {
		output += "\n" + result.Stderr
	}
	output += fmt.Sprintf("\n\n[CodeMapper Exit Code: %d | Duration: %s]", result.ExitCode, result.Duration.Round(time.Millisecond))

	// Truncate if needed
	const maxOutput = 20000
	if len(output) > maxOutput {
		output = output[:maxOutput] + "\n\n... [output truncated, showing first 20000 characters]"
	}

	return output, nil
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
