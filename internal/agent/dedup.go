// Package agent provides deduplication for vulnerability findings.
// Provides deduplication logic.
//
// Uses type-specific fingerprinting to correctly deduplicate findings:
// - Cookie-based SQLi is GLOBAL (same cookie = same vuln across URLs)
// - Header injection is GLOBAL (same header = same vuln)
// - XSS considers injection context (HTML body != JS context)
// - CSTI considers template engine type
// - Most other vulns are per-endpoint + per-parameter
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// URL/Parameter normalization
// ---------------------------------------------------------------------------

// NormalizeURLForDedup strips fragments and trailing slashes, returns (host, path).
func NormalizeURLForDedup(rawURL string) (string, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", rawURL
	}
	return parsed.Host, strings.TrimRight(parsed.Path, "/")
}

var camelRegex = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// NormalizeParamName converts camelCase/kebab-case to snake_case lowercase.
func NormalizeParamName(param string) string {
	name := camelRegex.ReplaceAllString(param, "${1}_${2}")
	name = strings.ReplaceAll(name, "-", "_")
	return strings.ToLower(name)
}

// ---------------------------------------------------------------------------
// Fingerprint generation (type-specific)
// ---------------------------------------------------------------------------

// Fingerprint represents a hashable finding identity.
type Fingerprint string

// GenericFingerprint creates a standard fingerprint: (type, host, path, param).
func GenericFingerprint(vulnType, rawURL, param, context string) Fingerprint {
	host, path := NormalizeURLForDedup(rawURL)
	if context != "" {
		return Fingerprint(fmt.Sprintf("%s|%s|%s|%s|%s", vulnType, host, path, strings.ToLower(param), context))
	}
	return Fingerprint(fmt.Sprintf("%s|%s|%s|%s", vulnType, host, path, strings.ToLower(param)))
}

// XSSFingerprint considers injection context. Same param + different context = DIFFERENT.
func XSSFingerprint(rawURL, param, context, sink, source string) Fingerprint {
	// Check for global DOM XSS (shared JS source)
	if rootCause := detectXSSRootCause(param, context, sink, source); rootCause != "" {
		host, _ := NormalizeURLForDedup(rawURL)
		return Fingerprint(fmt.Sprintf("XSS_GLOBAL|%s|%s|%s", host, rootCause, context))
	}
	host, path := NormalizeURLForDedup(rawURL)
	return Fingerprint(fmt.Sprintf("XSS|%s|%s|%s|%s", host, path, strings.ToLower(param), context))
}

func detectXSSRootCause(param, context, sink, source string) string {
	// postMessage -> eval (global event handler in shared JS)
	if param == "postMessage" || param == "window.postMessage" ||
		source == "postMessage" || source == "window.postMessage" {
		sinkName := strings.ToLower(sink)
		if strings.Contains(sinkName, "eval") {
			return "postMessage_eval_global"
		}
		return fmt.Sprintf("postMessage_%s_global", sinkName)
	}
	// location.search -> document.write (global searchLogger)
	if param == "location.search" && context == "dom_xss" {
		if strings.Contains(strings.ToLower(sink), "document.write") {
			return "location_search_docwrite_global"
		}
	}
	return ""
}

// SQLiFingerprint handles cookie-based (GLOBAL) vs param-based (per-endpoint).
func SQLiFingerprint(param, rawURL string) Fingerprint {
	paramLower := strings.ToLower(param)

	// Cookie-based: global vulnerability
	if strings.HasPrefix(paramLower, "cookie:") {
		cookieName := strings.TrimSpace(strings.SplitN(paramLower, ":", 2)[1])
		return Fingerprint(fmt.Sprintf("SQLI|cookie|%s", cookieName))
	}
	// Header-based: global vulnerability
	if strings.HasPrefix(paramLower, "header:") {
		headerName := strings.TrimSpace(strings.SplitN(paramLower, ":", 2)[1])
		return Fingerprint(fmt.Sprintf("SQLI|header|%s", headerName))
	}
	// URL/POST param: per-endpoint
	host, path := NormalizeURLForDedup(rawURL)
	name := strings.ToLower(strings.TrimSpace(param))
	return Fingerprint(fmt.Sprintf("SQLI|param|%s|%s|%s", host, path, name))
}

// CSTIFingerprint handles client-side (page-level) vs server-side (param-level).
func CSTIFingerprint(rawURL, param, engine string) Fingerprint {
	host, path := NormalizeURLForDedup(rawURL)
	clientSide := map[string]bool{
		"angular": true, "vue": true, "knockout": true, "ember": true, "react": true,
	}
	if clientSide[strings.ToLower(engine)] {
		// Same page + same engine = one finding
		return Fingerprint(fmt.Sprintf("CSTI|%s|%s|%s", host, path, engine))
	}
	// Server-side: each parameter is separate
	return Fingerprint(fmt.Sprintf("CSTI|%s|%s|%s|%s", host, path, strings.ToLower(param), engine))
}

// IDORFingerprint keys on (endpoint, resource_type).
func IDORFingerprint(rawURL, resourceType string) Fingerprint {
	host, path := NormalizeURLForDedup(rawURL)
	return Fingerprint(fmt.Sprintf("IDOR|%s|%s|%s", host, path, resourceType))
}

// JWTFingerprint keys on (domain, vuln_type, token_hash).
func JWTFingerprint(rawURL, vulnType, token string) Fingerprint {
	host, _ := NormalizeURLForDedup(rawURL)
	if token != "" {
		h := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(h[:4])
		return Fingerprint(fmt.Sprintf("JWT|%s|%s|%s", host, vulnType, tokenHash))
	}
	return Fingerprint(fmt.Sprintf("JWT|%s|%s", host, vulnType))
}

// XXEFingerprint: XXE is endpoint-level, not parameter-level.
func XXEFingerprint(rawURL string) Fingerprint {
	parsed, _ := url.Parse(rawURL)
	if parsed == nil {
		return Fingerprint(fmt.Sprintf("XXE|%s", rawURL))
	}
	return Fingerprint(fmt.Sprintf("XXE|%s|%s|%s", parsed.Scheme, parsed.Host, strings.TrimRight(parsed.Path, "/")))
}

// HeaderInjectionFingerprint: GLOBAL per header name.
func HeaderInjectionFingerprint(headerName string) Fingerprint {
	return Fingerprint(fmt.Sprintf("HEADER_INJECTION|%s", strings.ToLower(headerName)))
}

// ---------------------------------------------------------------------------
// Deduplication engine
// ---------------------------------------------------------------------------

// DedupFindings removes duplicate findings using type-specific fingerprinting.
// Order is preserved; the first occurrence wins.
func DedupFindings(findings []*Finding) []*Finding {
	seen := make(map[Fingerprint]bool)
	var result []*Finding

	for _, f := range findings {
		fp := fingerprintFinding(f)
		if !seen[fp] {
			seen[fp] = true
			result = append(result, f)
		}
	}
	return result
}

// fingerprintFinding selects the correct fingerprint strategy per vuln type.
func fingerprintFinding(f *Finding) Fingerprint {
	param, _ := f.Evidence["parameter"].(string)
	context, _ := f.Evidence["context"].(string)

	switch strings.ToUpper(f.Type) {
	case "XSS":
		sink, _ := f.Evidence["sink"].(string)
		source, _ := f.Evidence["source"].(string)
		return XSSFingerprint(f.URL, param, context, sink, source)
	case "SQLI", "SQL INJECTION":
		return SQLiFingerprint(param, f.URL)
	case "CSTI", "SSTI", "TEMPLATE INJECTION":
		engine, _ := f.Evidence["template_engine"].(string)
		return CSTIFingerprint(f.URL, param, engine)
	case "IDOR":
		resType, _ := f.Evidence["resource_type"].(string)
		return IDORFingerprint(f.URL, resType)
	case "JWT":
		token, _ := f.Evidence["token"].(string)
		return JWTFingerprint(f.URL, f.Type, token)
	case "XXE":
		return XXEFingerprint(f.URL)
	case "HEADER INJECTION", "CRLF":
		headerName, _ := f.Evidence["header_name"].(string)
		return HeaderInjectionFingerprint(headerName)
	default:
		return GenericFingerprint(f.Type, f.URL, param, context)
	}
}
