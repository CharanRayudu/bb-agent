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

// dockerfilePaths are paths we probe for Dockerfile and Docker Compose files.
var dockerfilePaths = []string{
	"/Dockerfile",
	"/docker/Dockerfile",
	"/deploy/Dockerfile",
	"/docker-compose.yml",
	"/docker-compose.yaml",
	"/docker-compose.override.yml",
	"/.dockerignore",
}

// dangerousPorts are ports that should not be exposed in production containers.
var dangerousPorts = map[string]string{
	"22":    "SSH — should not be exposed from container",
	"23":    "Telnet — plaintext protocol",
	"3306":  "MySQL — database should not be publicly exposed",
	"5432":  "PostgreSQL — database should not be publicly exposed",
	"6379":  "Redis — no-auth by default, should not be exposed",
	"27017": "MongoDB — should not be publicly exposed",
	"9200":  "Elasticsearch — should not be publicly exposed",
	"2375":  "Docker daemon (unauthenticated) — CRITICAL exposure",
	"2376":  "Docker daemon TLS",
	"10250": "Kubelet — should not be exposed from container",
}

func runContainerScan(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	var findings []*base.Finding
	root := strings.TrimRight(targetURL, "/")

	for _, path := range dockerfilePaths {
		url := root + path
		content, status, err := fetchFile(ctx, client, url)
		if err != nil || status != 200 || len(content) == 0 {
			continue
		}
		if looksLikeHTML(content) {
			continue
		}

		if strings.Contains(strings.ToLower(path), "dockerfile") {
			findings = append(findings, analyzeDockerfile(url, path, content)...)
		} else if strings.Contains(path, "docker-compose") {
			findings = append(findings, analyzeDockerCompose(url, path, content)...)
		}
	}
	return findings
}

func analyzeDockerfile(url, filePath, content string) []*base.Finding {
	var findings []*base.Finding
	lines := strings.Split(content, "\n")

	hasUser := false
	hasHealthcheck := false
	imageLines := []string{}

	for lineNum, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		upper := strings.ToUpper(line)

		// Track USER instruction
		if strings.HasPrefix(upper, "USER ") {
			hasUser = true
			user := strings.TrimSpace(line[5:])
			if user == "root" || user == "0" {
				findings = append(findings, &base.Finding{
					Type:       "Container-RootUser",
					URL:        url,
					Severity:   base.SeverityHigh,
					Confidence: 0.95,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":     filePath,
						"line":     lineNum + 1,
						"code":     line,
						"finding":  "Container explicitly runs as root user",
					},
					Payload: fmt.Sprintf("USER root at line %d", lineNum+1),
				})
			}
		}

		// Track HEALTHCHECK
		if strings.HasPrefix(upper, "HEALTHCHECK") {
			hasHealthcheck = true
		}

		// Track FROM for image analysis
		if strings.HasPrefix(upper, "FROM ") {
			imageLines = append(imageLines, line)
			imageName := strings.TrimSpace(line[5:])
			// Check for :latest tag (or no tag)
			if strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":") {
				findings = append(findings, &base.Finding{
					Type:       "Container-LatestTag",
					URL:        url,
					Severity:   base.SeverityMedium,
					Confidence: 0.90,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":    filePath,
						"line":    lineNum + 1,
						"code":    line,
						"image":   imageName,
						"finding": "Using :latest or untagged image prevents reproducible builds",
					},
					Payload: fmt.Sprintf("Unpinned image: %s", imageName),
				})
			}
		}

		// Check ENV/ARG for secrets
		if strings.HasPrefix(upper, "ENV ") || strings.HasPrefix(upper, "ARG ") {
			if containsSecretKeyword(line) {
				findings = append(findings, &base.Finding{
					Type:       "Container-SecretEnv",
					URL:        url,
					Severity:   base.SeverityCritical,
					Confidence: 0.85,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":    filePath,
						"line":    lineNum + 1,
						"code":    redactDockerfileLine(line),
						"finding": "Secret value baked into image layer via ENV/ARG",
					},
					Payload: fmt.Sprintf("Secret in Dockerfile ENV/ARG at line %d", lineNum+1),
				})
			}
		}

		// Check ADD with HTTP URL (remote file fetch — can be MITM'd)
		if strings.HasPrefix(upper, "ADD ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && (strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://")) {
				findings = append(findings, &base.Finding{
					Type:       "Container-RemoteADD",
					URL:        url,
					Severity:   base.SeverityMedium,
					Confidence: 0.88,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":     filePath,
						"line":     lineNum + 1,
						"code":     line,
						"source":   parts[1],
						"finding":  "ADD with remote URL is not verified — prefer COPY + curl with checksum verification",
					},
					Payload: fmt.Sprintf("Remote ADD from %s", parts[1]),
				})
			}
		}

		// Check EXPOSE for dangerous ports
		if strings.HasPrefix(upper, "EXPOSE ") {
			port := strings.TrimSpace(line[7:])
			port = strings.Split(port, "/")[0] // strip /tcp, /udp
			if reason, dangerous := dangerousPorts[port]; dangerous {
				findings = append(findings, &base.Finding{
					Type:       "Container-DangerousPort",
					URL:        url,
					Severity:   base.SeverityMedium,
					Confidence: 0.82,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":    filePath,
						"line":    lineNum + 1,
						"code":    line,
						"port":    port,
						"reason":  reason,
					},
					Payload: fmt.Sprintf("Exposed port %s: %s", port, reason),
				})
			}
		}

		// Check RUN with package install — flag if using apt/yum without --no-install-recommends
		if strings.HasPrefix(upper, "RUN ") && (strings.Contains(line, "apt-get install") || strings.Contains(line, "apt install")) {
			if !strings.Contains(line, "--no-install-recommends") {
				findings = append(findings, &base.Finding{
					Type:       "Container-BloatedLayer",
					URL:        url,
					Severity:   base.SeverityLow,
					Confidence: 0.80,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"file":    filePath,
						"line":    lineNum + 1,
						"code":    line,
						"finding": "apt-get install without --no-install-recommends increases attack surface",
					},
					Payload: fmt.Sprintf("Bloated layer at line %d", lineNum+1),
				})
			}
		}

		// Check COPY --chown for unusual ownership
		if strings.HasPrefix(upper, "COPY ") && strings.Contains(line, "--chown=root") {
			findings = append(findings, &base.Finding{
				Type:       "Container-RootChown",
				URL:        url,
				Severity:   base.SeverityLow,
				Confidence: 0.75,
				Agent:      "devsecops",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"file":    filePath,
					"line":    lineNum + 1,
					"code":    line,
					"finding": "Files copied with root ownership restrict runtime security",
				},
				Payload: fmt.Sprintf("Root-owned COPY at line %d", lineNum+1),
			})
		}
	}

	// Synthesized findings after full parse
	if !hasUser && len(imageLines) > 0 {
		findings = append(findings, &base.Finding{
			Type:       "Container-NoUserSet",
			URL:        url,
			Severity:   base.SeverityHigh,
			Confidence: 0.92,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"finding": "Dockerfile does not set a non-root USER — container runs as root by default",
			},
			Payload: "No USER instruction found — container runs as root",
		})
	}

	if !hasHealthcheck && len(imageLines) > 0 {
		findings = append(findings, &base.Finding{
			Type:       "Container-NoHealthcheck",
			URL:        url,
			Severity:   base.SeverityLow,
			Confidence: 0.80,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"finding": "No HEALTHCHECK instruction — orchestrators cannot detect unhealthy containers",
			},
			Payload: "No HEALTHCHECK instruction in Dockerfile",
		})
	}

	_ = imageLines
	return findings
}

var composePrivilegedRe = regexp.MustCompile(`(?m)^\s+privileged:\s+true`)
var composePidHostRe = regexp.MustCompile(`(?m)pid:\s+host`)
var composeNetworkHostRe = regexp.MustCompile(`(?m)network_mode:\s+['"']?host['"']?`)
var composeSensitiveMountRe = regexp.MustCompile(`(?m)-\s+(/var/run/docker\.sock|/etc/passwd|/etc/shadow|/proc|/sys)`)

func analyzeDockerCompose(url, filePath, content string) []*base.Finding {
	var findings []*base.Finding

	if composePrivilegedRe.MatchString(content) {
		findings = append(findings, &base.Finding{
			Type:       "Container-Privileged",
			URL:        url,
			Severity:   base.SeverityCritical,
			Confidence: 0.97,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"finding": "privileged: true grants container full host capabilities — equivalent to root on host",
			},
			Payload: "privileged: true in Docker Compose",
		})
	}

	if composePidHostRe.MatchString(content) {
		findings = append(findings, &base.Finding{
			Type:       "Container-PidNamespace",
			URL:        url,
			Severity:   base.SeverityHigh,
			Confidence: 0.92,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"finding": "pid: host shares host PID namespace — container can see and signal host processes",
			},
			Payload: "pid: host in Docker Compose",
		})
	}

	if composeNetworkHostRe.MatchString(content) {
		findings = append(findings, &base.Finding{
			Type:       "Container-HostNetwork",
			URL:        url,
			Severity:   base.SeverityMedium,
			Confidence: 0.88,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"finding": "network_mode: host disables network isolation — container shares host network stack",
			},
			Payload: "network_mode: host in Docker Compose",
		})
	}

	matches := composeSensitiveMountRe.FindAllString(content, -1)
	for _, m := range matches {
		path := strings.TrimSpace(strings.TrimLeft(m, "- "))
		severity := base.SeverityHigh
		if path == "/var/run/docker.sock" {
			severity = base.SeverityCritical
		}
		findings = append(findings, &base.Finding{
			Type:       "Container-SensitiveMount",
			URL:        url,
			Severity:   severity,
			Confidence: 0.93,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"file":    filePath,
				"mount":   path,
				"finding": fmt.Sprintf("Sensitive host path %s mounted into container", path),
			},
			Payload: fmt.Sprintf("Sensitive volume mount: %s", path),
		})
	}

	return findings
}

// trivyOutput is the JSON output from `trivy image --format json`.
type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Severity         string   `json:"Severity"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			CVSS             map[string]struct{ V3Score float64 } `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func runTrivy(ctx context.Context, image string) ([]*base.Finding, error) {
	cmd := exec.CommandContext(ctx, "trivy", "image", "--format", "json", "--quiet", image)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("trivy failed: %w", err)
	}

	var output trivyOutput
	if err := json.Unmarshal(out.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("trivy JSON parse error: %w", err)
	}

	var findings []*base.Finding
	for _, result := range output.Results {
		for _, v := range result.Vulnerabilities {
			sev := mapGrypeSeverity(v.Severity) // same mapping as grype
			var cvss float64
			for _, c := range v.CVSS {
				if c.V3Score > cvss {
					cvss = c.V3Score
				}
			}
			findings = append(findings, &base.Finding{
				Type:       "Container-CVE",
				URL:        image,
				Severity:   sev,
				Confidence: 0.95,
				Agent:      "devsecops",
				Timestamp:  time.Now(),
				Evidence: map[string]interface{}{
					"cve":      v.VulnerabilityID,
					"package":  v.PkgName,
					"version":  v.InstalledVersion,
					"fixed_in": v.FixedVersion,
					"target":   result.Target,
					"title":    v.Title,
					"cvss":     cvss,
					"tool":     "trivy",
				},
				Payload: fmt.Sprintf("%s@%s — %s", v.PkgName, v.InstalledVersion, v.VulnerabilityID),
			})
		}
	}
	return findings, nil
}

var secretKeywords = []string{
	"password", "passwd", "secret", "api_key", "apikey",
	"token", "private_key", "auth_token", "access_key", "credential",
}

func containsSecretKeyword(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range secretKeywords {
		if strings.Contains(lower, kw) && strings.Contains(line, "=") {
			// Make sure there's an actual value (not just a key name)
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && len(strings.TrimSpace(parts[1])) > 3 {
				return true
			}
		}
	}
	return false
}

func redactDockerfileLine(line string) string {
	if idx := strings.Index(line, "="); idx >= 0 {
		key := line[:idx+1]
		return key + "***REDACTED***"
	}
	return line
}
