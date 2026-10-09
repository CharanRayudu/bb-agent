package policy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	CodeAuthorized           = "authorized"
	CodeAuthorizationMissing = "authorization_missing"
	CodeOutsideWindow        = "outside_window"
	CodeAuthorizationExpired = "authorization_expired"
	CodeActionProhibited     = "action_prohibited"
	CodeSchemeNotAllowed     = "scheme_not_allowed"
	CodeOutOfScope           = "out_of_scope"
	CodePortNotAuthorized    = "port_not_authorized"
	CodePrivateAddress       = "private_address"
	CodeMetadataAddress      = "metadata_address"
	CodeUnrestrictedShell    = "unrestricted_shell_denied"
	CodeRiskNotAuthorized    = "risk_not_authorized"
	CodeApprovalRequired     = "approval_required"
	CodeApprovalDenied       = "approval_denied"
	CodeApprovalExpired      = "approval_expired"
	CodeBudgetExhausted      = "budget_exhausted"
	CodeInvalidTarget        = "invalid_target"
)

// Engine evaluates one subject against an authorization record.
// It does not perform I/O. The caller resolves DNS first.
type Engine struct{}

func (e Engine) Decide(auth *Authorization, subject Subject, approval *Approval, now time.Time) Decision {
	if auth == nil {
		return deny(CodeAuthorizationMissing, "no authorization record for this engagement")
	}
	if !auth.NotBefore.IsZero() && now.Before(auth.NotBefore) {
		return deny(CodeOutsideWindow, "authorization window has not started")
	}
	if !auth.ExpiresAt.IsZero() && !now.Before(auth.ExpiresAt) {
		return deny(CodeAuthorizationExpired, "authorization has expired")
	}
	if containsFold(auth.ProhibitedActions, subject.ActionType) {
		return deny(CodeActionProhibited, "action type is prohibited by the authorization record")
	}
	if !subject.Local {
		if d := checkDestination(*auth, subject); !d.Allowed {
			return d
		}
	}
	if subject.Shell && !auth.AllowUnrestrictedShell {
		return deny(CodeUnrestrictedShell, "unrestricted shell execution is not authorized for this engagement")
	}
	if d := checkRisk(*auth, subject, approval, now); !d.Allowed {
		return d
	}
	if auth.MaxRequests > 0 && auth.RequestsUsed >= auth.MaxRequests {
		return deny(CodeBudgetExhausted, "request budget for this authorization is exhausted")
	}
	return Decision{Allowed: true, Code: CodeAuthorized, Reason: "action is inside the authorization record"}
}

func checkDestination(auth Authorization, subject Subject) Decision {
	scheme := strings.ToLower(subject.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	if !schemeAllowed(auth, scheme) {
		return deny(CodeSchemeNotAllowed, "protocol "+scheme+" is not allowed")
	}
	host := normalizeHost(subject.Host)
	if host == "" {
		return deny(CodeOutOfScope, "action has no target host")
	}
	port := effectivePort(subject.Port, scheme)
	if excluded(auth, host, port, scheme) {
		return deny(CodeOutOfScope, "target is on the authorization exclusion list")
	}
	if !authorizedHost(auth, host) {
		return deny(CodeOutOfScope, "host "+host+" is not an authorized target")
	}
	if !authorizedPort(auth, host, port, scheme) {
		return deny(CodePortNotAuthorized, fmt.Sprintf("port %d is not authorized for %s", port, host))
	}
	for _, raw := range subject.IPs {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		if isMetadata(ip) && !explicitIP(auth, ip) {
			return deny(CodeMetadataAddress, "resolved address is a cloud metadata endpoint")
		}
		if isPrivate(ip) && !explicitIP(auth, ip) {
			return deny(CodePrivateAddress, "resolved address is private, loopback, or link-local and is not an explicit target")
		}
	}
	if host != "" && len(subject.IPs) == 0 && net.ParseIP(host) == nil {
		return deny(CodeOutOfScope, "destination was not resolved")
	}
	return Decision{Allowed: true, Code: CodeAuthorized}
}

func checkRisk(auth Authorization, subject Subject, approval *Approval, now time.Time) Decision {
	risk := subject.Risk
	if risk == "" {
		risk = RiskActive
	}
	if requiresExplicitGrant(auth.Autonomy, risk) && !containsRisk(auth.ExplicitGrants, risk) {
		return deny(CodeRiskNotAuthorized, "risk class "+string(risk)+" requires an explicit grant on the authorization")
	}
	if !needsApproval(auth.Autonomy, risk) {
		return Decision{Allowed: true}
	}
	if approval == nil || approval.Status == "" || approval.Status == "pending" {
		return deny(CodeApprovalRequired, "human approval is required before this action can run")
	}
	if approval.Status == "denied" {
		return deny(CodeApprovalDenied, "approval was denied")
	}
	if approval.Status != "approved" {
		return deny(CodeApprovalRequired, "approval is not in an approved state")
	}
	if !approval.ExpiresAt.IsZero() && !now.Before(approval.ExpiresAt) {
		return deny(CodeApprovalExpired, "approval has expired")
	}
	return Decision{Allowed: true}
}

func needsApproval(level Autonomy, risk Risk) bool {
	switch level {
	case AutonomyL1:
		return true
	case AutonomyL2:
		return risk != RiskPassive
	case AutonomyL3:
		return risk == RiskDestructive || risk == RiskCredential || risk == RiskExfiltration
	case AutonomyL4:
		return risk != RiskPassive
	default:
		return true
	}
}

func requiresExplicitGrant(level Autonomy, risk Risk) bool {
	switch risk {
	case RiskDestructive, RiskCredential, RiskExfiltration:
		return level == AutonomyL3 || level == AutonomyL4
	default:
		return false
	}
}

func schemeAllowed(auth Authorization, scheme string) bool {
	allowed := auth.AllowedProtocols
	if len(allowed) == 0 {
		allowed = []string{"http", "https"}
	}
	return containsFold(allowed, scheme)
}

func authorizedHost(auth Authorization, host string) bool {
	for _, target := range auth.Targets {
		if hostMatch(target.Host, host, auth.AllowSubdomains) {
			return true
		}
	}
	return false
}

func authorizedPort(auth Authorization, host string, port int, scheme string) bool {
	for _, target := range auth.Targets {
		if !hostMatch(target.Host, host, auth.AllowSubdomains) {
			continue
		}
		if effectivePort(target.Port, firstNonEmpty(target.Scheme, scheme)) == port {
			return true
		}
	}
	return false
}

func excluded(auth Authorization, host string, port int, scheme string) bool {
	for _, target := range auth.Exclusions {
		if hostMatch(target.Host, host, false) && effectivePort(target.Port, firstNonEmpty(target.Scheme, scheme)) == port {
			return true
		}
	}
	return false
}

func hostMatch(pattern, host string, subdomains bool) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if subdomains && strings.HasSuffix(host, "."+pattern) {
		return true
	}
	return false
}

func explicitIP(auth Authorization, ip net.IP) bool {
	for _, target := range auth.Targets {
		tip := net.ParseIP(normalizeHost(target.Host))
		if tip != nil && tip.Equal(ip) {
			return true
		}
	}
	return false
}

func isMetadata(ip net.IP) bool {
	return ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}

func isPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func effectivePort(port int, scheme string) int {
	if port != 0 {
		return port
	}
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func containsRisk(list []Risk, want Risk) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func deny(code, reason string) Decision {
	return Decision{Allowed: false, Code: code, Reason: reason}
}

// ParseTarget extracts an exact scheme, host, and port from a URL.
func ParseTarget(raw string) (Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return Target{}, err
	}
	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return Target{}, fmt.Errorf("target is missing a host")
	}
	port := 0
	if p := parsed.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return Target{}, fmt.Errorf("invalid port")
		}
		port = n
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("unsupported scheme %s", scheme)
	}
	return Target{Scheme: scheme, Host: host, Port: port}, nil
}

// AuthorizationForTarget builds the record created when an operator explicitly
// starts a flow. It authorizes that exact host and port only.
func AuthorizationForTarget(flowID, rawTarget string, level Autonomy, owner string, now time.Time) (Authorization, error) {
	target, err := ParseTarget(rawTarget)
	if err != nil {
		return Authorization{}, err
	}
	if level == "" {
		level = AutonomyL3
	}
	if owner == "" {
		owner = "operator"
	}
	return Authorization{
		ID:           "auth:" + flowID,
		EngagementID: flowID,
		FlowID:       flowID,
		Owner:        owner,
		Autonomy:     level,
		Targets:      []Target{target},
		NotBefore:    now.Add(-time.Second),
		ExpiresAt:    now.Add(24 * time.Hour),
	}, nil
}
