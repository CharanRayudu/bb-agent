package devsecops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
)

// sastPattern defines a native SAST rule.
type sastPattern struct {
	id          string
	name        string
	regex       *regexp.Regexp
	languages   []string // file extensions this applies to
	severity    string
	confidence  float64
	cwe         string
	remediation string
}

var sastPatterns = []sastPattern{
	// SQL Injection
	{
		id: "SAST-SQLi-001", name: "SQL Injection — String Concatenation",
		regex:      regexp.MustCompile(`(?i)(execute|query|exec|db\.query|cursor\.execute|mysql_query|pg_query|sqlite3\.execute)\s*\(.*\+\s*(request\.|req\.|params\.|input|user|query|data|body)`),
		languages:  []string{".py", ".js", ".ts", ".php", ".rb", ".java"},
		severity:   base.SeverityHigh,
		confidence: 0.80,
		cwe:        "CWE-89",
		remediation: "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
	},
	{
		id: "SAST-SQLi-002", name: "SQL Injection — Format String",
		regex:      regexp.MustCompile(`(?i)(query|execute|exec)\s*[(:=]\s*[f'"](SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*%[s\d]`),
		languages:  []string{".py", ".js", ".ts", ".php", ".rb"},
		severity:   base.SeverityHigh,
		confidence: 0.82,
		cwe:        "CWE-89",
		remediation: "Replace f-string/format SQL with parameterized queries.",
	},
	// Command Injection
	{
		id: "SAST-CMDi-001", name: "Command Injection — os.system / exec",
		regex:      regexp.MustCompile(`(?i)(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen|exec\.Command|child_process\.exec|shell_exec|passthru|system|popen)\s*\([^)]*\+`),
		languages:  []string{".py", ".js", ".ts", ".php", ".go", ".rb"},
		severity:   base.SeverityCritical,
		confidence: 0.78,
		cwe:        "CWE-78",
		remediation: "Use parameterized command execution (e.g., subprocess with list args). Never use shell=True with user input.",
	},
	{
		id: "SAST-CMDi-002", name: "Command Injection — shell=True",
		regex:      regexp.MustCompile(`(?i)shell\s*=\s*True`),
		languages:  []string{".py"},
		severity:   base.SeverityHigh,
		confidence: 0.70,
		cwe:        "CWE-78",
		remediation: "Avoid shell=True. Pass command as a list of arguments.",
	},
	// Path Traversal
	{
		id: "SAST-PTrav-001", name: "Path Traversal — open() with user input",
		regex:      regexp.MustCompile(`(?i)(open|readFile|readFileSync|file_get_contents|fopen|io\.ReadFile)\s*\([^)]*\b(request\.|req\.|params\.|input|user|query|filename|path)\b`),
		languages:  []string{".py", ".js", ".ts", ".php", ".go", ".rb"},
		severity:   base.SeverityHigh,
		confidence: 0.75,
		cwe:        "CWE-22",
		remediation: "Validate and sanitize file paths. Use os.path.abspath() and ensure the resolved path stays within the allowed base directory.",
	},
	// XSS
	{
		id: "SAST-XSS-001", name: "Reflected XSS — innerHTML",
		regex:      regexp.MustCompile(`(?i)\.innerHTML\s*=\s*[^;]*\b(location\.|document\.URL|window\.location|history\.state|search\.|hash\.|query\.|params\.|input|user)`),
		languages:  []string{".js", ".ts", ".jsx", ".tsx", ".html"},
		severity:   base.SeverityHigh,
		confidence: 0.80,
		cwe:        "CWE-79",
		remediation: "Use textContent instead of innerHTML. Sanitize output with DOMPurify before inserting HTML.",
	},
	{
		id: "SAST-XSS-002", name: "Reflected XSS — dangerouslySetInnerHTML",
		regex:      regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{`),
		languages:  []string{".jsx", ".tsx", ".js", ".ts"},
		severity:   base.SeverityMedium,
		confidence: 0.70,
		cwe:        "CWE-79",
		remediation: "Avoid dangerouslySetInnerHTML. If required, sanitize with DOMPurify before use.",
	},
	// SSRF
	{
		id: "SAST-SSRF-001", name: "SSRF — HTTP request with user-supplied URL",
		regex:      regexp.MustCompile(`(?i)(requests\.get|requests\.post|http\.get|fetch|axios\.(get|post|request)|urllib\.request\.urlopen|curl_exec|file_get_contents)\s*\([^)]*\b(request\.|req\.|params\.|input|user|url|target|host|endpoint)`),
		languages:  []string{".py", ".js", ".ts", ".php", ".go", ".rb"},
		severity:   base.SeverityHigh,
		confidence: 0.75,
		cwe:        "CWE-918",
		remediation: "Validate URLs against an allowlist of approved domains. Block requests to private IP ranges (RFC 1918, 169.254.x.x).",
	},
	// XXE
	{
		id: "SAST-XXE-001", name: "XXE — XML parser without entity restriction",
		regex:      regexp.MustCompile(`(?i)(xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|DOMParser|XMLReader|SAXParser|xml\.dom\.minidom\.parseString)\s*\(`),
		languages:  []string{".py", ".js", ".ts", ".java", ".php"},
		severity:   base.SeverityHigh,
		confidence: 0.68,
		cwe:        "CWE-611",
		remediation: "Disable external entity processing: set resolve_entities=False, use defusedxml in Python, or configure XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false in Java.",
	},
	// Insecure Deserialization
	{
		id: "SAST-Deser-001", name: "Insecure Deserialization — pickle.loads",
		regex:      regexp.MustCompile(`(?i)pickle\.(loads|load)\s*\(`),
		languages:  []string{".py"},
		severity:   base.SeverityHigh,
		confidence: 0.88,
		cwe:        "CWE-502",
		remediation: "Never unpickle data from untrusted sources. Use JSON or MessagePack for serialization.",
	},
	{
		id: "SAST-Deser-002", name: "Insecure Deserialization — eval() with external data",
		regex:      regexp.MustCompile(`(?i)\beval\s*\([^)]*\b(request\.|req\.|params\.|input|user|query|data|body|JSON\.parse)\b`),
		languages:  []string{".js", ".ts", ".php", ".py", ".rb"},
		severity:   base.SeverityCritical,
		confidence: 0.82,
		cwe:        "CWE-95",
		remediation: "Remove eval() calls. Use JSON.parse() for JSON data, never eval().",
	},
	// Hardcoded Credentials
	{
		id: "SAST-HardCred-001", name: "Hardcoded Password in Source",
		regex:      regexp.MustCompile(`(?i)(password|passwd|secret|apikey|api_key)\s*[:=]\s*['\"](?!.*{)([A-Za-z0-9!@#$%^&*()_+\-=]{8,})['\"]`),
		languages:  []string{".py", ".js", ".ts", ".go", ".java", ".php", ".rb", ".kt", ".swift"},
		severity:   base.SeverityHigh,
		confidence: 0.73,
		cwe:        "CWE-798",
		remediation: "Store credentials in environment variables or a secrets manager (Vault, AWS Secrets Manager). Never hardcode in source.",
	},
	// Open Redirect
	{
		id: "SAST-OpenRedirect-001", name: "Open Redirect",
		regex:      regexp.MustCompile(`(?i)(redirect|location|header\s*\(\s*['"]\s*Location)\s*.*\b(request\.|req\.|params\.|query\.|input|url|next|return_to|redirect_to)\b`),
		languages:  []string{".py", ".js", ".ts", ".php", ".rb"},
		severity:   base.SeverityMedium,
		confidence: 0.72,
		cwe:        "CWE-601",
		remediation: "Validate redirect destinations against an allowlist of trusted domains.",
	},
	// SSTI
	{
		id: "SAST-SSTI-001", name: "Server-Side Template Injection — Jinja2",
		regex:      regexp.MustCompile(`(?i)(render_template_string|jinja2\.Template)\s*\([^)]*\b(request\.|req\.|params\.|input|user|data)\b`),
		languages:  []string{".py"},
		severity:   base.SeverityCritical,
		confidence: 0.83,
		cwe:        "CWE-94",
		remediation: "Never pass user input directly to render_template_string(). Use render_template() with static template files.",
	},
}

// sourcePaths are files we try to fetch from the target for SAST analysis.
var sourcePaths = []string{
	"/index.js",
	"/server.js",
	"/app.js",
	"/main.js",
	"/src/index.js",
	"/src/app.js",
	"/src/server.js",
	"/app.py",
	"/main.py",
	"/app.go",
	"/main.go",
	"/index.php",
	"/wp-login.php",
	"/login.php",
	"/upload.php",
}

type sourceFile struct {
	path    string
	url     string
	content string
	ext     string
}

func runSAST(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	// Try semgrep first
	if path, err := exec.LookPath("semgrep"); err == nil && path != "" {
		if findings, err := runSemgrep(ctx, targetURL); err == nil {
			return findings
		}
	}

	// Native fallback: fetch source files and scan
	return runSASTNative(ctx, client, targetURL)
}

func runSASTNative(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	var findings []*base.Finding

	files := fetchSourceFiles(ctx, client, targetURL)
	for _, f := range files {
		findings = append(findings, scanFileWithPatterns(f)...)
	}
	return findings
}

func fetchSourceFiles(ctx context.Context, client *http.Client, baseURL string) []sourceFile {
	var files []sourceFile
	base := strings.TrimRight(baseURL, "/")

	for _, path := range sourcePaths {
		url := base + path
		content, status, err := fetchFile(ctx, client, url)
		if err != nil || status != 200 || len(content) < 20 {
			continue
		}
		if looksLikeHTML(content) {
			continue
		}

		ext := fileExt(path)
		files = append(files, sourceFile{
			path:    path,
			url:     url,
			content: content,
			ext:     ext,
		})
	}
	return files
}

func scanFileWithPatterns(f sourceFile) []*base.Finding {
	var findings []*base.Finding
	lines := strings.Split(f.content, "\n")

	for _, pat := range sastPatterns {
		if !appliesToExt(pat.languages, f.ext) {
			continue
		}

		for lineNum, line := range lines {
			if !pat.regex.MatchString(line) {
				continue
			}

			match := pat.regex.FindString(line)
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 120 {
				trimmed = trimmed[:120] + "..."
			}

			findings = append(findings, &base.Finding{
				Type:       pat.id,
				URL:        f.url,
				Severity:   pat.severity,
				Confidence: pat.confidence,
				Agent:      "devsecops",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"rule_id":     pat.id,
					"rule_name":   pat.name,
					"file":        f.path,
					"line":        lineNum + 1,
					"code":        trimmed,
					"match":       match,
					"cwe":         pat.cwe,
					"tool":        "native-sast",
				},
				Payload:   fmt.Sprintf("Line %d: %s", lineNum+1, trimmed),
			})
		}
	}
	return findings
}

// semgrepOutput is the JSON output format from `semgrep --json`.
type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func runSemgrep(ctx context.Context, targetURL string) ([]*base.Finding, error) {
	cmd := exec.CommandContext(ctx,
		"semgrep", "--config=p/security-audit", "--json",
		"--no-rewrite-rule-ids", "--quiet",
		targetURL,
	)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		// Semgrep exits non-zero when findings exist — check if we got JSON output
		if out.Len() == 0 {
			return nil, fmt.Errorf("semgrep produced no output: %w", err)
		}
	}

	var output semgrepOutput
	if err := json.Unmarshal(out.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("semgrep JSON parse error: %w", err)
	}

	var findings []*base.Finding
	for _, r := range output.Results {
		sev := mapSemgrepSeverity(r.Extra.Severity)
		findings = append(findings, &base.Finding{
			Type:       "SAST-Semgrep",
			URL:        targetURL,
			Severity:   sev,
			Confidence: 0.85,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"rule_id":  r.CheckID,
				"file":     r.Path,
				"line":     r.Start.Line,
				"message":  r.Extra.Message,
				"code":     r.Extra.Lines,
				"metadata": r.Extra.Metadata,
				"tool":     "semgrep",
			},
			Payload: fmt.Sprintf("%s:%d — %s", r.Path, r.Start.Line, r.CheckID),
		})
	}
	return findings, nil
}

func mapSemgrepSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "ERROR", "CRITICAL":
		return base.SeverityCritical
	case "WARNING", "HIGH":
		return base.SeverityHigh
	case "INFO", "LOW":
		return base.SeverityLow
	default:
		return base.SeverityMedium
	}
}

func appliesToExt(languages []string, ext string) bool {
	if len(languages) == 0 {
		return true
	}
	for _, l := range languages {
		if l == ext {
			return true
		}
	}
	return false
}

func fileExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return path[idx:]
}
