package policy

import "time"

// Autonomy is the engagement's approved oversight level.
// L4 is stricter than L3. It is not an unrestricted mode.
type Autonomy string

const (
	AutonomyL1 Autonomy = "L1"
	AutonomyL2 Autonomy = "L2"
	AutonomyL3 Autonomy = "L3"
	AutonomyL4 Autonomy = "L4"
)

// Risk is the side-effect class of one action.
type Risk string

const (
	RiskPassive      Risk = "passive"
	RiskActive       Risk = "active"
	RiskExploitation Risk = "exploitation"
	RiskDestructive  Risk = "destructive"
	RiskCredential   Risk = "credential_access"
	RiskExfiltration Risk = "exfiltration"
)

// Target is one explicit host and port. An empty port means the scheme default
// (80 for http, 443 for https). Subdomains are not included.
type Target struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
}

// Authorization is the signed-in-practice record for one engagement.
// A flow may run active tests only while one of these records covers the action.
type Authorization struct {
	ID                     string    `json:"id"`
	EngagementID           string    `json:"engagement_id"`
	FlowID                 string    `json:"flow_id"`
	Owner                  string    `json:"owner"`
	Autonomy               Autonomy  `json:"autonomy"`
	Targets                []Target  `json:"targets"`
	Exclusions             []Target  `json:"exclusions,omitempty"`
	AllowedProtocols       []string  `json:"allowed_protocols,omitempty"`
	ProhibitedActions      []string  `json:"prohibited_actions,omitempty"`
	ExplicitGrants         []Risk    `json:"explicit_grants,omitempty"`
	AllowUnrestrictedShell bool      `json:"allow_unrestricted_shell,omitempty"`
	AllowSubdomains        bool      `json:"allow_subdomains,omitempty"`
	MaxRequests            int       `json:"max_requests,omitempty"`
	RequestsUsed           int       `json:"requests_used,omitempty"`
	NotBefore              time.Time `json:"not_before"`
	ExpiresAt              time.Time `json:"expires_at"`
}

// Subject is the network and risk view of an action. The execution gateway
// fills IPs immediately before this is evaluated.
type Subject struct {
	ActionType string
	Risk       Risk
	Phase      string
	Scheme     string
	Host       string
	Path       string
	Port       int
	IPs        []string
	Local      bool
	Shell      bool
}

// Approval is a durable human decision for one action or one phase.
type Approval struct {
	ID        string
	FlowID    string
	ActionKey string
	Phase     string
	Status    string
	Actor     string
	Reason    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Decision is a machine-readable authorization result.
type Decision struct {
	Allowed bool
	Code    string
	Reason  string
}
