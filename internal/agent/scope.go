package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var targetTextRe = regexp.MustCompile(`https?://[^\s"'<>]+|(?:\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)|(?:/[A-Za-z0-9._~!$&()*+,;=:@%/\-?#[\]]+)`)

var localArtifactPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/proc/",
	"/sys/",
	"/etc/",
	"/usr/",
	"/opt/",
	"/root/",
	"/home/",
	"/workspace/",
	"./",
	"../",
}

// ScopeEngine enforces target scope boundaries to prevent out-of-scope scanning.
type ScopeEngine struct {
	AllowedDomains []string    // e.g., ["example.com", "*.example.com"]
	AllowedIPs     []net.IPNet // CIDR ranges
	AllowedPort    int         // Non-zero: only this port is in-scope (e.g., 3001 for http://host:3001)
	ExcludedPaths  []string    // e.g., ["/logout", "/admin/delete"]
	RawTarget      string      // Original target string
}

// NewScopeEngine parses a target string and auto-generates scope rules.
func NewScopeEngine(target string) *ScopeEngine {
	se := &ScopeEngine{
		RawTarget:     target,
		ExcludedPaths: []string{"/logout", "/signout", "/sign-out", "/log-out"},
	}
	se.parseTarget(target)
	return se
}

// parseTarget extracts domains and IPs from the target string.
func (se *ScopeEngine) parseTarget(target string) {
	cleaned := strings.TrimSpace(target)

	for _, prefix := range []string{"http://", "https://"} {
		cleaned = strings.TrimPrefix(cleaned, prefix)
	}

	host := cleaned
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		portPart := host[idx+1:]
		if len(portPart) <= 5 {
			host = host[:idx]
			if p, err := strconv.Atoi(portPart); err == nil && p > 0 {
				se.AllowedPort = p
			}
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		se.AllowedIPs = append(se.AllowedIPs, net.IPNet{IP: ip, Mask: mask})
		return
	}

	se.AllowedDomains = append(se.AllowedDomains, host)
	se.AllowedDomains = append(se.AllowedDomains, "*."+host)
}

// IsInScope checks if a given URL or IP is within the allowed scope.
func (se *ScopeEngine) IsInScope(targetURL string) bool {
	if len(se.AllowedDomains) == 0 && len(se.AllowedIPs) == 0 {
		return true
	}

	if !strings.Contains(targetURL, "://") {
		targetURL = "http://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	path := parsed.Path

	// Port enforcement: if the original target specified an explicit non-default port
	// (e.g., http://86.48.30.37:3001), only requests to that exact port are in-scope.
	if se.AllowedPort != 0 && effectivePort(parsed) != se.AllowedPort {
		return false
	}

	for _, excluded := range se.ExcludedPaths {
		if strings.HasPrefix(path, excluded) {
			return false
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, allowed := range se.AllowedIPs {
			if allowed.Contains(ip) {
				return true
			}
		}
		return false
	}

	for _, allowed := range se.AllowedDomains {
		if matchDomain(allowed, host) {
			return true
		}
	}

	return false
}

// ValidateToolArgs performs tool-aware scope validation instead of scanning raw JSON blobs.
func (se *ScopeEngine) ValidateToolArgs(toolName string, rawArgs json.RawMessage) (bool, string) {
	switch toolName {
	case "think", "report_findings", "complete_task", "update_brain", "cg_add_node", "cg_update_node", "cg_add_edge", "oob_generate", "oob_poll", "generate_payloads":
		return true, ""
	case "execute_command":
		var params struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(rawArgs, &params); err != nil {
			return false, fmt.Sprintf("BLOCKED: Invalid execute_command arguments: %v", err)
		}
		if strings.TrimSpace(params.Command) == "" {
			return false, "BLOCKED: execute_command requires a non-empty command."
		}
		return se.IsCommandInScope(params.Command)
	case "visual_crawl":
		var params struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(rawArgs, &params); err != nil {
			return false, fmt.Sprintf("BLOCKED: Invalid visual_crawl arguments: %v", err)
		}
		return se.validateTargets([]string{params.URL})
	default:
		var params map[string]interface{}
		if err := json.Unmarshal(rawArgs, &params); err != nil {
			return true, ""
		}

		var targets []string
		for _, key := range []string{"target", "target_url", "url"} {
			if value, ok := params[key].(string); ok && strings.TrimSpace(value) != "" {
				targets = append(targets, value)
			}
		}
		return se.validateTargets(targets)
	}
}

// IsCommandInScope extracts URLs/IPs from a shell command and validates each.
func (se *ScopeEngine) IsCommandInScope(command string) (bool, string) {
	return se.validateTargets(extractTargetsFromText(command))
}

func (se *ScopeEngine) validateTargets(targets []string) (bool, string) {
	for _, t := range targets {
		normalized := se.normalizeTarget(strings.Trim(strings.TrimSpace(t), `"'`))
		if normalized == "" {
			continue
		}

		// Heuristic: If it doesn't have a dot (like a domain/IP) and doesn't start with a protocol,
		// it's likely a local Linux path from a command (e.g. /etc/passwd) or library (BeautifulSoup/).
		// We skip scope validation for these to prevent false-positive blocks.
		if !strings.Contains(normalized, ".") && !strings.HasPrefix(normalized, "http") && !strings.HasPrefix(normalized, "ws") {
			continue
		}

		if !se.IsInScope(normalized) {
			return false, fmt.Sprintf("BLOCKED: Target '%s' is out of scope. %s", normalized, se.String())
		}
	}
	return true, ""
}

func (se *ScopeEngine) normalizeTarget(raw string) string {
	if raw == "" {
		return ""
	}

	for _, prefix := range localArtifactPrefixes {
		if strings.HasPrefix(raw, prefix) {
			return ""
		}
	}

	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		base := se.baseTargetURL()
		if base != nil {
			if ref, err := url.Parse(raw); err == nil {
				return base.ResolveReference(ref).String()
			}
		}
	}

	return raw
}

func (se *ScopeEngine) baseTargetURL() *url.URL {
	baseTarget := strings.TrimSpace(se.RawTarget)
	if baseTarget == "" {
		return nil
	}
	if !strings.Contains(baseTarget, "://") {
		baseTarget = "http://" + baseTarget
	}
	parsed, err := url.Parse(baseTarget)
	if err != nil {
		return nil
	}
	return parsed
}

// effectivePort returns the port a URL will actually connect to.
// If the URL has an explicit port it returns that; otherwise it returns
// the well-known default for the scheme (80 for http, 443 for https).
func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// matchDomain checks if a host matches a domain pattern (supports wildcards).
func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	if pattern == host {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix)
	}

	return false
}

// extractTargetsFromText finds URLs, IPs, and root-relative paths in free-form text.
func extractTargetsFromText(text string) []string {
	matches := targetTextRe.FindAllString(text, -1)
	targets := make([]string, 0, len(matches))
	for _, match := range matches {
		cleaned := strings.Trim(match, "\"'()[]{}<>,")
		// Skip shell variable expansions (e.g. http://host$p, http://host${var}) —
		// these are loop variables in bash commands, not real targets.
		if cleaned == "" || strings.Contains(cleaned, "$") {
			continue
		}
		targets = append(targets, cleaned)
	}
	return targets
}

// String returns a human-readable representation of the scope.
func (se *ScopeEngine) String() string {
	var parts []string
	for _, d := range se.AllowedDomains {
		parts = append(parts, d)
	}
	for _, ip := range se.AllowedIPs {
		parts = append(parts, ip.String())
	}
	return fmt.Sprintf("Scope: %s", strings.Join(parts, ", "))
}
