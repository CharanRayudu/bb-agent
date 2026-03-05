package agent

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// RedirectInsight encapsulates what the tracker learned from 302 analysis
type RedirectInsight struct {
	LoginURL         string // The detected login/auth page
	RedirectCount    int    // How many times we've been redirected there
	ShouldPivot      bool   // True if agent should attack the login page
	ShouldInjectAuth bool   // True if brain has creds but no cookies yet
	Message          string // Human-readable message to inject
}

// RedirectTracker detects repeated HTTP 302 redirects to login pages
// and generates actionable intelligence for the agent loop.
type RedirectTracker struct {
	mu             sync.Mutex
	redirectCounts map[string]int // login URL → redirect count
	loginPatterns  *regexp.Regexp // compiled pattern for login URL detection
}

// NewRedirectTracker creates a tracker with common login URL patterns
func NewRedirectTracker() *RedirectTracker {
	// Match common login/auth page patterns in Location headers or response bodies
	patterns := `(?i)(location:\s*\S*(login|signin|auth|session|sso|cas|oauth|saml)[^\s]*|HTTP/[\d.]+ 30[1-3])`
	compiled, _ := regexp.Compile(patterns)

	return &RedirectTracker{
		redirectCounts: make(map[string]int),
		loginPatterns:  compiled,
	}
}

// loginURLPatterns extracts login page URLs from tool output containing redirects
var loginURLExtractor = regexp.MustCompile(`(?i)(?:location:\s*|< location:\s*|→\s*|redirect(?:ed)?\s+to\s+)(\S+)`)

// Analyze inspects tool output for redirect patterns and returns insight
func (rt *RedirectTracker) Analyze(toolOutput string) *RedirectInsight {
	if toolOutput == "" {
		return nil
	}

	lower := strings.ToLower(toolOutput)

	// Check for redirect indicators
	has302 := strings.Contains(lower, "302") || strings.Contains(lower, "301") ||
		strings.Contains(lower, "303") || strings.Contains(lower, "redirect")
	hasLoginRef := strings.Contains(lower, "login") || strings.Contains(lower, "signin") ||
		strings.Contains(lower, "auth") || strings.Contains(lower, "session")

	if !has302 || !hasLoginRef {
		return nil
	}

	// Extract the login URL
	loginURL := rt.extractLoginURL(toolOutput)
	if loginURL == "" {
		// Fallback: mark generic login detection
		loginURL = "(login page)"
	}

	rt.mu.Lock()
	rt.redirectCounts[loginURL]++
	count := rt.redirectCounts[loginURL]
	rt.mu.Unlock()

	if count < 3 {
		return nil // Not enough redirects yet
	}

	return &RedirectInsight{
		LoginURL:      loginURL,
		RedirectCount: count,
		ShouldPivot:   true,
		Message: fmt.Sprintf(
			"⚠️ AUTH WALL DETECTED: %d requests redirected to %s. "+
				"PIVOT STRATEGY: (1) Try default credentials (admin/admin, admin/password). "+
				"(2) Look for auth bypass (SQL injection in login form, IDOR). "+
				"(3) Search for exposed backup configs or .env files with credentials. "+
				"(4) If you have credentials, use them to get a session cookie.",
			count, loginURL,
		),
	}
}

// extractLoginURL pulls the actual URL from redirect output
func (rt *RedirectTracker) extractLoginURL(output string) string {
	matches := loginURLExtractor.FindStringSubmatch(output)
	if len(matches) > 1 {
		url := strings.TrimSpace(matches[1])
		// Clean up common trailing chars
		url = strings.TrimRight(url, "\"'>;,)")
		return url
	}

	// Fallback: search for common login page paths
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, pattern := range []string{"login.php", "/login", "/signin", "/auth", "/session"} {
			if idx := strings.Index(lower, pattern); idx >= 0 {
				// Extract the URL-like segment around the match
				start := strings.LastIndex(line[:idx], "http")
				if start == -1 {
					start = strings.LastIndex(line[:idx], "/")
				}
				if start >= 0 {
					end := idx + len(pattern)
					for end < len(line) && line[end] != ' ' && line[end] != '"' && line[end] != '\'' {
						end++
					}
					return strings.TrimSpace(line[start:end])
				}
				return pattern
			}
		}
	}
	return ""
}

// GetTopLoginURL returns the most-redirected login URL (for Brain injection)
func (rt *RedirectTracker) GetTopLoginURL() (string, int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var topURL string
	var topCount int
	for url, count := range rt.redirectCounts {
		if count > topCount {
			topURL = url
			topCount = count
		}
	}
	return topURL, topCount
}

// Reset clears all tracked redirects (used on pipeline restart)
func (rt *RedirectTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.redirectCounts = make(map[string]int)
}
