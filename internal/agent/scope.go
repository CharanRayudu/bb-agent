package agent

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ScopeEngine enforces target scope boundaries to prevent out-of-scope scanning
type ScopeEngine struct {
	AllowedDomains []string    // e.g., ["example.com", "*.example.com"]
	AllowedIPs     []net.IPNet // CIDR ranges
	ExcludedPaths  []string    // e.g., ["/logout", "/admin/delete"]
	RawTarget      string      // Original target string
}

// NewScopeEngine parses a target string and auto-generates scope rules
func NewScopeEngine(target string) *ScopeEngine {
	se := &ScopeEngine{
		RawTarget:     target,
		ExcludedPaths: []string{"/logout", "/signout", "/sign-out", "/log-out"},
	}
	se.parseTarget(target)
	return se
}

// parseTarget extracts domains and IPs from the target string
func (se *ScopeEngine) parseTarget(target string) {
	cleaned := strings.TrimSpace(target)

	// Strip protocol for domain extraction
	for _, prefix := range []string{"http://", "https://"} {
		cleaned = strings.TrimPrefix(cleaned, prefix)
	}

	// Strip path and port
	host := cleaned
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Only strip if this looks like a port (after an IP or domain)
		portPart := host[idx+1:]
		if len(portPart) <= 5 {
			host = host[:idx]
		}
	}

	// Check if it's an IP
	if ip := net.ParseIP(host); ip != nil {
		// Single IP — allow /32
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		se.AllowedIPs = append(se.AllowedIPs, net.IPNet{IP: ip, Mask: mask})
	} else {
		// It's a domain
		se.AllowedDomains = append(se.AllowedDomains, host)
		// Also allow wildcard subdomains
		se.AllowedDomains = append(se.AllowedDomains, "*."+host)
	}
}

// IsInScope checks if a given URL or IP is within the allowed scope
func (se *ScopeEngine) IsInScope(targetURL string) bool {
	if len(se.AllowedDomains) == 0 && len(se.AllowedIPs) == 0 {
		return true // No scope defined = everything allowed
	}

	// Parse the URL
	if !strings.Contains(targetURL, "://") {
		targetURL = "http://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	path := parsed.Path

	// Check excluded paths
	for _, excluded := range se.ExcludedPaths {
		if strings.HasPrefix(path, excluded) {
			return false
		}
	}

	// Check IP scope
	if ip := net.ParseIP(host); ip != nil {
		for _, allowed := range se.AllowedIPs {
			if allowed.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Check domain scope
	for _, allowed := range se.AllowedDomains {
		if matchDomain(allowed, host) {
			return true
		}
	}

	return false
}

// IsCommandInScope extracts URLs/IPs from a shell command and validates each
func (se *ScopeEngine) IsCommandInScope(command string) (bool, string) {
	targets := extractTargetsFromCommand(command)

	for _, t := range targets {
		if !se.IsInScope(t) {
			return false, fmt.Sprintf("BLOCKED: Target '%s' is out of scope. Allowed scope: %v", t, se.AllowedDomains)
		}
	}
	return true, ""
}

// matchDomain checks if a host matches a domain pattern (supports wildcards)
func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	if pattern == host {
		return true
	}

	// Wildcard match: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	}

	return false
}

// extractTargetsFromCommand finds URLs and IPs in a shell command string
func extractTargetsFromCommand(cmd string) []string {
	var targets []string
	parts := strings.Fields(cmd)

	for _, p := range parts {
		// Skip flags
		if strings.HasPrefix(p, "-") {
			continue
		}
		// Check for URLs
		if strings.Contains(p, "http://") || strings.Contains(p, "https://") {
			targets = append(targets, p)
			continue
		}
		// Check for IPs
		if ip := net.ParseIP(p); ip != nil {
			targets = append(targets, p)
			continue
		}
		// Check for host:port patterns
		if strings.Contains(p, ":") && !strings.HasPrefix(p, "/") {
			host := strings.Split(p, ":")[0]
			if net.ParseIP(host) != nil || strings.Contains(host, ".") {
				targets = append(targets, p)
			}
		}
	}
	return targets
}

// String returns a human-readable representation of the scope
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
