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

type dependency struct {
	Name      string
	Version   string
	Ecosystem string // npm, pypi, go, maven, rubygems, cargo
}

type vulnEntry struct {
	CVE         string
	Severity    string
	Confidence  float64
	Description string
	FixedIn     string
	CVSS        float64
}

// knownVulnerablePackages maps "ecosystem:package" to known CVEs.
// This is a curated representative set — production would use OSV/NVD/GitHub Advisory APIs.
var knownVulnerablePackages = map[string][]vulnEntry{
	// npm
	"npm:lodash": {
		{CVE: "CVE-2021-23337", Severity: base.SeverityHigh, Confidence: 0.95, CVSS: 7.2,
			Description: "Command injection via zip.unzip", FixedIn: "4.17.21"},
		{CVE: "CVE-2020-8203", Severity: base.SeverityHigh, Confidence: 0.95, CVSS: 7.4,
			Description: "Prototype pollution in zipObjectDeep", FixedIn: "4.17.19"},
	},
	"npm:axios": {
		{CVE: "CVE-2023-45857", Severity: base.SeverityHigh, Confidence: 0.94, CVSS: 8.8,
			Description: "CSRF vulnerability via cross-origin headers", FixedIn: "1.6.0"},
	},
	"npm:express": {
		{CVE: "CVE-2024-29041", Severity: base.SeverityMedium, Confidence: 0.90, CVSS: 6.1,
			Description: "Open redirect via malformed URLs", FixedIn: "4.19.2"},
	},
	"npm:jsonwebtoken": {
		{CVE: "CVE-2022-23529", Severity: base.SeverityHigh, Confidence: 0.93, CVSS: 8.8,
			Description: "Arbitrary file write via secretOrPublicKey", FixedIn: "9.0.0"},
	},
	"npm:semver": {
		{CVE: "CVE-2022-25883", Severity: base.SeverityHigh, Confidence: 0.92, CVSS: 7.5,
			Description: "ReDoS via unterminated version string", FixedIn: "7.5.2"},
	},
	"npm:minimatch": {
		{CVE: "CVE-2022-3517", Severity: base.SeverityHigh, Confidence: 0.91, CVSS: 7.5,
			Description: "ReDoS via braces pattern expansion", FixedIn: "3.0.5"},
	},
	"npm:node-fetch": {
		{CVE: "CVE-2022-0235", Severity: base.SeverityHigh, Confidence: 0.90, CVSS: 8.8,
			Description: "Exposure of sensitive information to unauthorized actor", FixedIn: "2.6.7"},
	},
	"npm:qs": {
		{CVE: "CVE-2022-24999", Severity: base.SeverityHigh, Confidence: 0.92, CVSS: 7.5,
			Description: "Prototype poisoning via parseObject", FixedIn: "6.11.0"},
	},
	"npm:tough-cookie": {
		{CVE: "CVE-2023-26136", Severity: base.SeverityHigh, Confidence: 0.91, CVSS: 9.8,
			Description: "Prototype pollution via cookie domain", FixedIn: "4.1.3"},
	},
	"npm:xml2js": {
		{CVE: "CVE-2023-0842", Severity: base.SeverityMedium, Confidence: 0.90, CVSS: 6.5,
			Description: "Prototype pollution via deeply nested XML", FixedIn: "0.5.0"},
	},
	// pypi
	"pypi:django": {
		{CVE: "CVE-2024-27351", Severity: base.SeverityHigh, Confidence: 0.93, CVSS: 7.5,
			Description: "ReDoS in django.utils.text.Truncator.words()", FixedIn: "4.2.11"},
		{CVE: "CVE-2023-36053", Severity: base.SeverityHigh, Confidence: 0.93, CVSS: 7.5,
			Description: "ReDoS via EmailValidator and URLValidator", FixedIn: "3.2.20"},
	},
	"pypi:pillow": {
		{CVE: "CVE-2023-44271", Severity: base.SeverityHigh, Confidence: 0.91, CVSS: 7.5,
			Description: "Uncontrolled resource consumption in ImageFont", FixedIn: "10.0.1"},
	},
	"pypi:cryptography": {
		{CVE: "CVE-2023-49083", Severity: base.SeverityMedium, Confidence: 0.90, CVSS: 5.9,
			Description: "NULL pointer dereference in PKCS12 parsing", FixedIn: "41.0.6"},
	},
	"pypi:requests": {
		{CVE: "CVE-2023-32681", Severity: base.SeverityMedium, Confidence: 0.90, CVSS: 6.1,
			Description: "Proxy-Authorization header leak on redirect", FixedIn: "2.31.0"},
	},
	"pypi:sqlalchemy": {
		{CVE: "CVE-2019-7548", Severity: base.SeverityHigh, Confidence: 0.88, CVSS: 8.1,
			Description: "SQL injection via column or table name", FixedIn: "1.3.0"},
	},
	"pypi:flask": {
		{CVE: "CVE-2023-30861", Severity: base.SeverityHigh, Confidence: 0.92, CVSS: 7.5,
			Description: "Possible disclosure of permanent session cookie to wrong application", FixedIn: "2.3.2"},
	},
	// go modules
	"go:golang.org/x/net": {
		{CVE: "CVE-2023-44487", Severity: base.SeverityHigh, Confidence: 0.94, CVSS: 7.5,
			Description: "HTTP/2 Rapid Reset Attack (DDOS amplification)", FixedIn: "v0.17.0"},
	},
	"go:golang.org/x/crypto": {
		{CVE: "CVE-2022-27191", Severity: base.SeverityHigh, Confidence: 0.92, CVSS: 7.5,
			Description: "Panic in golang.org/x/crypto/ssh on invalid handshake", FixedIn: "v0.0.0-20220315160706"},
	},
	// Java / Maven
	"maven:org.apache.logging.log4j:log4j-core": {
		{CVE: "CVE-2021-44228", Severity: base.SeverityCritical, Confidence: 0.99, CVSS: 10.0,
			Description: "Log4Shell — JNDI injection via message lookup", FixedIn: "2.17.1"},
	},
	"maven:com.fasterxml.jackson.core:jackson-databind": {
		{CVE: "CVE-2022-42003", Severity: base.SeverityHigh, Confidence: 0.91, CVSS: 7.5,
			Description: "Deep wrapper array nesting leads to OOM", FixedIn: "2.13.4.2"},
	},
}

// dependencyFilePaths are files to probe for from the target.
var dependencyFilePaths = []string{
	"/package.json",
	"/requirements.txt",
	"/requirements/production.txt",
	"/requirements/base.txt",
	"/go.mod",
	"/Gemfile.lock",
	"/pom.xml",
	"/build.gradle",
	"/composer.json",
	"/Cargo.toml",
}

func runSCA(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	// Try Grype first
	if path, err := exec.LookPath("grype"); err == nil && path != "" {
		if findings, err := runGrype(ctx, targetURL); err == nil {
			return findings
		}
	}

	return runSCANative(ctx, client, targetURL)
}

func runSCANative(ctx context.Context, client *http.Client, targetURL string) []*base.Finding {
	var allFindings []*base.Finding
	root := strings.TrimRight(targetURL, "/")

	for _, path := range dependencyFilePaths {
		url := root + path
		content, status, err := fetchFile(ctx, client, url)
		if err != nil || status != 200 || len(content) == 0 {
			continue
		}
		if looksLikeHTML(content) {
			continue
		}

		var deps []dependency
		switch {
		case strings.HasSuffix(path, "package.json"):
			deps = parsePackageJSON(content)
		case strings.Contains(path, "requirements"):
			deps = parseRequirementsTxt(content)
		case strings.HasSuffix(path, "go.mod"):
			deps = parseGoMod(content)
		case strings.HasSuffix(path, "pom.xml"):
			deps = parsePomXML(content)
		case strings.HasSuffix(path, "Gemfile.lock"):
			deps = parseGemfileLock(content)
		}

		for _, dep := range deps {
			key := dep.Ecosystem + ":" + dep.Name
			vulns, ok := knownVulnerablePackages[key]
			if !ok {
				continue
			}
			for _, v := range vulns {
				if !isVersionVulnerable(dep.Version, v.FixedIn) {
					continue
				}
				allFindings = append(allFindings, &base.Finding{
					Type:       "SCA-CVE",
					URL:        url,
					Severity:   v.Severity,
					Confidence: v.Confidence,
					Agent:      "devsecops",
					Timestamp:  time.Now(),
					Evidence: map[string]interface{}{
						"cve":         v.CVE,
						"package":     dep.Name,
						"version":     dep.Version,
						"fixed_in":    v.FixedIn,
						"ecosystem":   dep.Ecosystem,
						"description": v.Description,
						"cvss":        v.CVSS,
						"file":        path,
						"tool":        "native-sca",
					},
					Payload: fmt.Sprintf("%s@%s — %s (%s)", dep.Name, dep.Version, v.CVE, v.Description),
				})
			}
		}
	}
	return allFindings
}

func parsePackageJSON(content string) []dependency {
	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pj); err != nil {
		return nil
	}

	var deps []dependency
	for name, ver := range pj.Dependencies {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm"})
	}
	for name, ver := range pj.DevDependencies {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm"})
	}
	return deps
}

var reqLineRe = regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)\s*[><=!~^]{1,2}\s*([\d.]+)`)

func parseRequirementsTxt(content string) []dependency {
	var deps []dependency
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		deps = append(deps, dependency{Name: strings.ToLower(m[1]), Version: m[2], Ecosystem: "pypi"})
	}
	return deps
}

var goModRequireRe = regexp.MustCompile(`^\s+([^\s]+)\s+(v[\d.]+)`)

func parseGoMod(content string) []dependency {
	var deps []dependency
	inRequire := false
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require (") {
			inRequire = true
			continue
		}
		if inRequire && strings.TrimSpace(line) == ")" {
			inRequire = false
			continue
		}
		if inRequire {
			m := goModRequireRe.FindStringSubmatch(line)
			if m != nil {
				deps = append(deps, dependency{Name: m[1], Version: m[2], Ecosystem: "go"})
			}
		}
	}
	return deps
}

var pomDepRe = regexp.MustCompile(`<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>`)

func parsePomXML(content string) []dependency {
	var deps []dependency
	matches := pomDepRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		deps = append(deps, dependency{
			Name:      m[1] + ":" + m[2],
			Version:   m[3],
			Ecosystem: "maven",
		})
	}
	return deps
}

var gemLockRe = regexp.MustCompile(`^\s{4}([a-z][a-z0-9_\-]+)\s+\(([\d.]+)\)`)

func parseGemfileLock(content string) []dependency {
	var deps []dependency
	for _, line := range strings.Split(content, "\n") {
		m := gemLockRe.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, dependency{Name: m[1], Version: m[2], Ecosystem: "rubygems"})
		}
	}
	return deps
}

func cleanVersion(v string) string {
	v = strings.TrimLeft(v, "^~>=<")
	v = strings.TrimSpace(v)
	return v
}

// isVersionVulnerable returns true if dep version is older than fixedIn.
// Simple semver major.minor.patch comparison; returns false on parse error (safe default).
func isVersionVulnerable(depVer, fixedIn string) bool {
	if depVer == "" || fixedIn == "" {
		return false
	}
	depParts := parseVersion(cleanVersion(depVer))
	fixParts := parseVersion(cleanVersion(fixedIn))
	if depParts == nil || fixParts == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if depParts[i] < fixParts[i] {
			return true
		}
		if depParts[i] > fixParts[i] {
			return false
		}
	}
	return false // equal → not vulnerable
}

var versionNumRe = regexp.MustCompile(`\d+`)

func parseVersion(v string) []int {
	// Strip 'v' prefix
	v = strings.TrimPrefix(v, "v")
	// Take only the numeric part before any dash/plus suffix
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	nums := make([]int, 3)
	for i, p := range parts {
		if i >= 3 {
			break
		}
		m := versionNumRe.FindString(p)
		if m == "" {
			return nil
		}
		var n int
		fmt.Sscanf(m, "%d", &n)
		nums[i] = n
	}
	return nums
}

// grypeOutput is the JSON output format from `grype --output json`.
type grypeOutput struct {
	Matches []struct {
		Vulnerability struct {
			ID          string                                          `json:"id"`
			Severity    string                                          `json:"severity"`
			CVSS        []struct{ Metrics struct{ BaseScore float64 } } `json:"cvss"`
			Description string                                          `json:"description"`
			Fix         struct{ Versions []string }                     `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
}

func runGrype(ctx context.Context, targetURL string) ([]*base.Finding, error) {
	cmd := exec.CommandContext(ctx, "grype", "--output", "json", targetURL)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("grype failed: %w", err)
	}

	var output grypeOutput
	if err := json.Unmarshal(out.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("grype JSON parse error: %w", err)
	}

	var findings []*base.Finding
	for _, m := range output.Matches {
		sev := mapGrypeSeverity(m.Vulnerability.Severity)
		var cvss float64
		if len(m.Vulnerability.CVSS) > 0 {
			cvss = m.Vulnerability.CVSS[0].Metrics.BaseScore
		}
		fixedIn := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixedIn = m.Vulnerability.Fix.Versions[0]
		}
		findings = append(findings, &base.Finding{
			Type:       "SCA-CVE",
			URL:        targetURL,
			Severity:   sev,
			Confidence: 0.95,
			Agent:      "devsecops",
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"cve":         m.Vulnerability.ID,
				"package":     m.Artifact.Name,
				"version":     m.Artifact.Version,
				"ecosystem":   m.Artifact.Type,
				"description": m.Vulnerability.Description,
				"cvss":        cvss,
				"fixed_in":    fixedIn,
				"tool":        "grype",
			},
			Payload: fmt.Sprintf("%s@%s — %s", m.Artifact.Name, m.Artifact.Version, m.Vulnerability.ID),
		})
	}
	return findings, nil
}

func mapGrypeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return base.SeverityCritical
	case "high":
		return base.SeverityHigh
	case "medium":
		return base.SeverityMedium
	case "low":
		return base.SeverityLow
	default:
		return base.SeverityInfo
	}
}
