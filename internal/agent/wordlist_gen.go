package agent

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// WordlistConfig controls which extraction sources are active and the output size.
type WordlistConfig struct {
	IncludePaths    bool
	IncludeParams   bool
	IncludeKeywords bool
	MaxEntries      int
}

// GenerateWordlist creates a target-specific wordlist from crawled content.
// It extracts: URL path segments, query parameters, form field names,
// JS variable names, comment keywords, page titles and REST path patterns.
func GenerateWordlist(crawledURLs []string, htmlContent []string, config WordlistConfig) []string {
	freq := make(map[string]int)

	if config.IncludePaths {
		for _, rawURL := range crawledURLs {
			for _, seg := range extractPathSegments(rawURL) {
				if isValidToken(seg) {
					freq[seg]++
				}
			}
		}
		// API path pattern detection (REST conventions)
		for _, rawURL := range crawledURLs {
			for _, pat := range detectRESTPatterns(rawURL) {
				if isValidToken(pat) {
					freq[pat]++
				}
			}
		}
	}

	if config.IncludeParams {
		for _, rawURL := range crawledURLs {
			for _, param := range extractQueryParams(rawURL) {
				if isValidToken(param) {
					freq[param]++
				}
			}
		}
		for _, html := range htmlContent {
			for _, name := range extractFormFields(html) {
				if isValidToken(name) {
					freq[name]++
				}
			}
		}
	}

	if config.IncludeKeywords {
		for _, html := range htmlContent {
			for _, kw := range extractHTMLKeywords(html) {
				if isValidToken(kw) {
					freq[kw]++
				}
			}
		}
	}

	// Deduplicate and sort by frequency (descending), then alphabetically
	type entry struct {
		word  string
		count int
	}
	entries := make([]entry, 0, len(freq))
	for w, c := range freq {
		entries = append(entries, entry{w, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].word < entries[j].word
	})

	maxEntries := config.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 5000
	}

	result := make([]string, 0, minInt(len(entries), maxEntries))
	for i, e := range entries {
		if i >= maxEntries {
			break
		}
		result = append(result, e.word)
	}
	return result
}

// extractPathSegments splits a URL path into non-empty segments.
func extractPathSegments(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback: treat rawURL as a plain path
		return splitPath(rawURL)
	}
	return splitPath(u.Path)
}

func splitPath(path string) []string {
	parts := strings.Split(path, "/")
	var segs []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip file extensions to get the base name
		if idx := strings.LastIndex(p, "."); idx > 0 {
			ext := strings.ToLower(p[idx:])
			if isWebExtension(ext) {
				p = p[:idx]
			}
		}
		if p != "" {
			segs = append(segs, p)
		}
	}
	return segs
}

func isWebExtension(ext string) bool {
	webExts := map[string]bool{
		".html": true, ".htm": true, ".php": true, ".asp": true, ".aspx": true,
		".jsp": true, ".js": true, ".css": true, ".json": true, ".xml": true,
		".txt": true, ".pdf": true, ".png": true, ".jpg": true, ".gif": true,
	}
	return webExts[ext]
}

// extractQueryParams returns parameter names from a URL's query string.
func extractQueryParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	params := make([]string, 0, len(q))
	for k := range q {
		params = append(params, k)
	}
	return params
}

// HTML attribute extractors.
var (
	idAttrRe       = regexp.MustCompile(`(?i)\bid\s*=\s*["']([^"']+)["']`)
	nameAttrRe     = regexp.MustCompile(`(?i)\bname\s*=\s*["']([^"']+)["']`)
	inputNameRe    = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']([^"']+)["']`)
	pageTitleRe    = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	htmlCommentRe  = regexp.MustCompile(`<!--(.*?)-->`)
	jsVarRe        = regexp.MustCompile(`(?i)(?:var|let|const)\s+(\w+)\s*=`)
	jsStringRe     = regexp.MustCompile(`["']([a-zA-Z][a-zA-Z0-9_\-]{2,31})["']`)
	apiPathRe      = regexp.MustCompile(`(?i)/api/v?\d*/([a-zA-Z][a-zA-Z0-9_\-]*)`)
)

// extractFormFields returns id and name attribute values from HTML.
func extractFormFields(html string) []string {
	var fields []string
	for _, m := range idAttrRe.FindAllStringSubmatch(html, -1) {
		fields = append(fields, m[1])
	}
	for _, m := range nameAttrRe.FindAllStringSubmatch(html, -1) {
		fields = append(fields, m[1])
	}
	for _, m := range inputNameRe.FindAllStringSubmatch(html, -1) {
		fields = append(fields, m[1])
	}
	return fields
}

// extractHTMLKeywords extracts keywords from page titles, JS variables, comments, and API strings.
func extractHTMLKeywords(html string) []string {
	var kws []string

	// Page titles
	for _, m := range pageTitleRe.FindAllStringSubmatch(html, -1) {
		for _, w := range tokenizeWords(m[1]) {
			kws = append(kws, w)
		}
	}

	// HTML comments
	for _, m := range htmlCommentRe.FindAllStringSubmatch(html, -1) {
		for _, w := range tokenizeWords(m[1]) {
			kws = append(kws, w)
		}
	}

	// JS variable names
	for _, m := range jsVarRe.FindAllStringSubmatch(html, -1) {
		kws = append(kws, m[1])
	}

	// Short JS string literals that look like identifiers
	for _, m := range jsStringRe.FindAllStringSubmatch(html, -1) {
		kws = append(kws, m[1])
	}

	return kws
}

// detectRESTPatterns extracts resource names from REST-style URL patterns.
// e.g. /api/v1/users/123 -> ["api", "users"]
func detectRESTPatterns(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	path := u.Path

	var patterns []string
	// Match /api/... patterns
	for _, m := range apiPathRe.FindAllStringSubmatch(path, -1) {
		patterns = append(patterns, m[1])
	}

	// Detect plural resource names (users, products, orders, etc.)
	// by looking for path segments followed by numeric IDs.
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if i+1 < len(parts) && isNumericID(parts[i+1]) {
			patterns = append(patterns, p)
		}
	}

	return patterns
}

var numericIDRe = regexp.MustCompile(`^\d+$`)

func isNumericID(s string) bool {
	return numericIDRe.MatchString(s) && len(s) <= 12
}

// tokenizeWords splits a string on whitespace and punctuation, lowercases, and filters.
var wordSplitRe = regexp.MustCompile(`[\s\-_/|:,.!?;()[\]{}'"]+`)

func tokenizeWords(s string) []string {
	var words []string
	for _, w := range wordSplitRe.Split(s, -1) {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) >= 3 && len(w) <= 32 {
			words = append(words, w)
		}
	}
	return words
}

// isValidToken checks a word is suitable for inclusion in a wordlist.
func isValidToken(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	// Must start with a letter
	if len(s) > 0 && (s[0] < 'a' || s[0] > 'z') && (s[0] < 'A' || s[0] > 'Z') {
		return false
	}
	// Skip purely numeric strings
	allDigits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
