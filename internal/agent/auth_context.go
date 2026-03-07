package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	authCookieRe      = regexp.MustCompile(`(?i)(?:set-cookie:\s*)?([A-Za-z0-9_.-]{1,64})=([^;\s,]+)`)
	authBearerRe      = regexp.MustCompile(`(?i)(?:authorization:\s*bearer|bearer)\s+([A-Za-z0-9._~+/=-]{8,})`)
	authBasicHeaderRe = regexp.MustCompile(`(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]+)`)
	authCredentialRe  = regexp.MustCompile(`\b([A-Za-z0-9_.@-]{1,64}):([^\s,;]{1,128})\b`)
	authLoginURLRe    = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+(?:login|signin|sign-in|auth|session|sso)[^\s"'<>]*|/[A-Za-z0-9._~!$&()*+,;=:@%/\-?#[\]]*(?:login|signin|sign-in|auth|session|sso)[A-Za-z0-9._~!$&()*+,;=:@%/\-?#[\]]*)`)
)

func ensureAuthState(auth **AuthState) *AuthState {
	if *auth == nil {
		*auth = &AuthState{}
	}
	if (*auth).Cookies == nil {
		(*auth).Cookies = make(map[string]string)
	}
	if (*auth).Credentials == nil {
		(*auth).Credentials = make(map[string]string)
	}
	if (*auth).Headers == nil {
		(*auth).Headers = make(map[string]string)
	}
	return *auth
}

func appendAuthNote(auth *AuthState, note string) bool {
	if auth == nil {
		return false
	}
	normalized := normalizeBrainNote(note)
	if normalized == "" {
		return false
	}
	for _, existing := range auth.Notes {
		if existing == normalized {
			return false
		}
	}
	auth.Notes = append(auth.Notes, normalized)
	return true
}

func mergeAuthContextFromNote(auth *AuthState, note string) bool {
	if auth == nil {
		return false
	}

	note = strings.TrimSpace(note)
	if note == "" {
		return false
	}

	changed := appendAuthNote(auth, note)

	if auth.LoginURL == "" {
		if match := authLoginURLRe.FindString(note); strings.TrimSpace(match) != "" {
			auth.LoginURL = strings.TrimSpace(match)
			changed = true
		}
	}

	if tokenMatch := authBearerRe.FindStringSubmatch(note); len(tokenMatch) == 2 {
		headerValue := "Bearer " + strings.TrimSpace(tokenMatch[1])
		if auth.Headers["Authorization"] != headerValue {
			auth.Headers["Authorization"] = headerValue
			auth.AuthMethod = "bearer"
			changed = true
		}
	}

	if basicMatch := authBasicHeaderRe.FindStringSubmatch(note); len(basicMatch) == 2 {
		headerValue := "Basic " + strings.TrimSpace(basicMatch[1])
		if auth.Headers["Authorization"] != headerValue {
			auth.Headers["Authorization"] = headerValue
			auth.AuthMethod = "basic"
			changed = true
		}
	}

	for _, match := range authCookieRe.FindAllStringSubmatch(note, -1) {
		name := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if name == "" || value == "" {
			continue
		}
		if strings.EqualFold(name, "path") || strings.EqualFold(name, "domain") || strings.EqualFold(name, "expires") {
			continue
		}
		if auth.Cookies[name] != value {
			auth.Cookies[name] = value
			auth.AuthMethod = "cookie"
			changed = true
		}
	}

	for _, match := range authCredentialRe.FindAllStringSubmatch(note, -1) {
		username := strings.TrimSpace(match[1])
		password := strings.TrimSpace(match[2])
		if username == "" || password == "" {
			continue
		}
		if strings.Contains(username, "http") || strings.Contains(password, "//") {
			continue
		}
		if auth.Credentials[username] != password {
			auth.Credentials[username] = password
			changed = true
		}
	}

	return changed
}

func buildAuthContextSummary(auth *AuthState) string {
	if auth == nil {
		return ""
	}

	var lines []string
	if auth.LoginURL != "" {
		lines = append(lines, fmt.Sprintf("Login URL: %s", auth.LoginURL))
	}
	if auth.AuthMethod != "" {
		lines = append(lines, fmt.Sprintf("Preferred auth method: %s", auth.AuthMethod))
	}
	if len(auth.Headers) > 0 {
		lines = append(lines, "Headers: "+formatKeyValuePairs(auth.Headers))
	}
	if len(auth.Cookies) > 0 {
		lines = append(lines, "Cookies: "+formatKeyValuePairs(auth.Cookies))
	}
	if len(auth.Credentials) > 0 {
		lines = append(lines, "Credentials: "+formatKeyValuePairs(auth.Credentials))
	}
	if len(auth.Notes) > 0 {
		limit := 3
		if len(auth.Notes) < limit {
			limit = len(auth.Notes)
		}
		lines = append(lines, "Notes: "+strings.Join(auth.Notes[:limit], " | "))
	}

	return strings.Join(lines, "\n")
}

func authPayload(auth *AuthState) map[string]interface{} {
	if auth == nil {
		return nil
	}

	payload := map[string]interface{}{}
	if len(auth.Cookies) > 0 {
		payload["cookies"] = cloneStringMap(auth.Cookies)
	}
	if len(auth.Credentials) > 0 {
		payload["credentials"] = cloneStringMap(auth.Credentials)
	}
	if len(auth.Headers) > 0 {
		payload["headers"] = cloneStringMap(auth.Headers)
	}
	if auth.LoginURL != "" {
		payload["login_url"] = auth.LoginURL
	}
	if auth.AuthMethod != "" {
		payload["auth_method"] = auth.AuthMethod
	}
	if len(auth.Notes) > 0 {
		payload["notes"] = append([]string(nil), auth.Notes...)
	}

	return payload
}

func enrichSwarmAgentSpec(baseTarget string, spec SwarmAgentSpec, auth *AuthState) SwarmAgentSpec {
	targetHint := strings.TrimSpace(spec.Target)
	if targetHint == "" {
		targetHint = extractTargetHint(spec.Context)
	}
	spec.Target = resolveDispatchTarget(baseTarget, targetHint)
	spec.Priority = normalizePriority(spec.Priority)

	if strings.TrimSpace(spec.Hypothesis) == "" {
		spec.Hypothesis = defaultHypothesis(spec, baseTarget)
	}
	if strings.TrimSpace(spec.Proof) == "" {
		spec.Proof = proofRequirementForSpec(spec.Type, spec.Context)
	}
	if !spec.RequiresAuth {
		spec.RequiresAuth = inferAuthRequirement(spec, auth)
	}
	if strings.TrimSpace(spec.AuthContext) == "" {
		spec.AuthContext = buildAuthContextSummary(auth)
	}

	return spec
}

func composeSpecialistContext(spec SwarmAgentSpec, context string) string {
	parts := make([]string, 0, 4)
	if trimmed := strings.TrimSpace(context); trimmed != "" {
		parts = append(parts, trimmed)
	}
	if trimmed := strings.TrimSpace(spec.Hypothesis); trimmed != "" {
		parts = append(parts, "Hypothesis: "+trimmed)
	}
	if trimmed := strings.TrimSpace(spec.Proof); trimmed != "" {
		parts = append(parts, "Promotion gate: "+trimmed)
	}
	if trimmed := strings.TrimSpace(spec.AuthContext); trimmed != "" {
		prefix := "Auth context available"
		if spec.RequiresAuth {
			prefix = "Preserve and reuse this auth context"
		}
		parts = append(parts, prefix+":\n"+trimmed)
	}
	return strings.Join(parts, "\n\n")
}

func inferAuthRequirement(spec SwarmAgentSpec, auth *AuthState) bool {
	lower := strings.ToLower(strings.Join([]string{spec.Type, spec.Target, spec.Context}, " "))
	switch {
	case strings.Contains(lower, "login"),
		strings.Contains(lower, "signin"),
		strings.Contains(lower, "auth"),
		strings.Contains(lower, "session"),
		strings.Contains(lower, "cookie"),
		strings.Contains(lower, "token"),
		strings.Contains(lower, "account"),
		strings.Contains(lower, "profile"),
		strings.Contains(lower, "dashboard"),
		strings.Contains(lower, "checkout"),
		strings.Contains(lower, "admin"):
		return true
	}

	if auth == nil {
		return false
	}

	switch normalizeSpecialistName(spec.Type) {
	case "authdiscovery", "apisecurity", "idor", "jwt", "businesslogic", "urlmaster":
		return true
	default:
		return false
	}
}

func defaultHypothesis(spec SwarmAgentSpec, baseTarget string) string {
	target := resolveDispatchTarget(baseTarget, spec.Target)
	if target == "" {
		target = baseTarget
	}
	kind := strings.TrimSpace(spec.Type)
	if kind == "" {
		kind = "specialist hypothesis"
	}
	return fmt.Sprintf("Narrowly test %s on %s and only escalate if reproducible proof is captured.", kind, target)
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func formatKeyValuePairs(input map[string]string) string {
	if len(input) == 0 {
		return ""
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, input[key]))
	}
	return strings.Join(pairs, "; ")
}
