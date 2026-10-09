package execution

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

// Action is the typed request every tool and specialist must present
// before an effect is allowed to happen.
type Action struct {
	ID              string            `json:"id"`
	EngagementID    string            `json:"engagement_id"`
	FlowID          string            `json:"flow_id"`
	ActorID         string            `json:"actor_id"`
	SkillID         string            `json:"skill_id"`
	ToolID          string            `json:"tool_id"`
	ActionType      string            `json:"action_type"`
	Phase           string            `json:"phase"`
	Scheme          string            `json:"scheme"`
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Path            string            `json:"path"`
	ResolvedIPs     []string          `json:"resolved_ips,omitempty"`
	Arguments       map[string]string `json:"arguments,omitempty"`
	Risk            policy.Risk       `json:"risk"`
	Timeout         time.Duration     `json:"timeout"`
	ApprovalID      string            `json:"approval_id,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key"`
	Local           bool              `json:"local"`
	Shell           bool              `json:"shell"`
	FollowRedirects bool              `json:"follow_redirects"`
	Digest          string            `json:"digest,omitempty"`
	ExtraTargets    []string          `json:"extra_targets,omitempty"`
}

// Decision is persisted for every authorization attempt.
type Decision struct {
	ID             string    `json:"id"`
	ActionID       string    `json:"action_id"`
	FlowID         string    `json:"flow_id"`
	Allowed        bool      `json:"allowed"`
	Code           string    `json:"code"`
	Reason         string    `json:"reason"`
	IdempotencyKey string    `json:"idempotency_key"`
	ActorID        string    `json:"actor_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// Result is the outcome of Execute.
type Result struct {
	Decision Decision `json:"decision"`
	Output   string   `json:"output,omitempty"`
}

// Status is the last known state of an action.
type Status struct {
	ActionID string   `json:"action_id"`
	State    string   `json:"state"`
	Decision Decision `json:"decision"`
}

func (a Action) subject(ips []string) policy.Subject {
	return policy.Subject{
		ActionType: a.ActionType,
		Risk:       a.Risk,
		Phase:      a.Phase,
		Scheme:     a.Scheme,
		Host:       a.Host,
		Path:       a.Path,
		Port:       a.Port,
		IPs:        ips,
		Local:      a.Local,
		Shell:      a.Shell,
	}
}

var commandURLRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ToolAction classifies an LLM tool call into an Action.
// Shell commands are never treated as authorized merely because a regex
// found a host. The gateway still applies the shell and approval rules.
func ToolAction(flowID, name, actor string, args json.RawMessage) Action {
	action := Action{
		FlowID:         flowID,
		EngagementID:   flowID,
		ActorID:        actor,
		ToolID:         name,
		IdempotencyKey: flowID + ":" + name + ":" + hashArgs(args),
		Arguments:      map[string]string{"raw": string(args)},
	}
	switch name {
	case "think", "complete_task", "update_brain", "report_findings", "cg_add_node", "cg_update_node", "cg_add_edge", "oob_generate", "oob_poll", "generate_payloads":
		action.ActionType = "control." + name
		action.Risk = policy.RiskPassive
		action.Phase = "control"
		action.Local = true
		action.SkillID = "control." + name
	case "execute_command":
		return shellAction(flowID, actor, args)
	case "run_security_tool":
		return SecurityToolAction(flowID, actor, args)
	case "visual_crawl":
		action.ActionType = "browser.navigate"
		action.Risk = policy.RiskPassive
		action.Phase = "recon"
		action.SkillID = "browser.crawl"
		applyFirstURL(&action, commandURLRe.FindString(string(args)))
	case "analyze_source_code":
		action.ActionType = "source.fetch"
		action.Risk = policy.RiskActive
		action.Phase = "recon"
		action.SkillID = "source.fetch"
		action.Shell = false
		urls := commandURLRe.FindAllString(string(args), -1)
		if len(urls) > 0 {
			applyFirstURL(&action, urls[0])
		}
		if len(urls) > 1 {
			action.ExtraTargets = append(action.ExtraTargets, urls[1:]...)
		}
	default:
		action.ActionType = "tool." + name
		action.Risk = policy.RiskActive
		action.Phase = "exploitation"
		action.SkillID = "tool." + name
		applyFirstURL(&action, commandURLRe.FindString(string(args)))
	}
	return action
}

func applyFirstURL(action *Action, raw string) {
	if raw == "" || action == nil {
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return
	}
	action.Scheme = parsed.Scheme
	action.Host = parsed.Hostname()
	action.Path = parsed.Path
	if parsed.Port() != "" {
		if target, err := policy.ParseTarget(raw); err == nil {
			action.Port = target.Port
		}
	}
}

func hashArgs(args json.RawMessage) string {
	sum := uint32(2166136261)
	for _, b := range args {
		sum ^= uint32(b)
		sum *= 16777619
	}
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = hexdigits[sum&0xf]
		sum >>= 4
	}
	return string(buf)
}

// Digest is a stable short hash for payloads and approval keys.
func Digest(value string) string {
	return hashArgs([]byte(value))
}

// HTTPAction builds a passive or caller-specified HTTP action for a specialist.
func HTTPAction(flowID, skillID, method, rawURL string) (Action, error) {
	target, err := policy.ParseTarget(rawURL)
	if err != nil {
		return Action{}, err
	}
	parsed, _ := url.Parse(rawURL)
	path := ""
	if parsed != nil {
		path = parsed.RequestURI()
	}
	risk := policy.RiskPassive
	phase := "recon"
	if method != "" && !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
		risk = policy.RiskActive
		phase = "exploitation"
	}
	digest := Digest(method + "\n" + rawURL)
	return Action{
		FlowID:          flowID,
		EngagementID:    flowID,
		SkillID:         skillID,
		ToolID:          "http.request",
		ActionType:      "http.request",
		Phase:           phase,
		Scheme:          target.Scheme,
		Host:            target.Host,
		Port:            target.Port,
		Path:            path,
		Risk:            risk,
		Digest:          digest,
		IdempotencyKey:  flowID + ":http:" + method + ":" + rawURL + ":" + digest,
		FollowRedirects: true,
		Arguments:       map[string]string{"method": method, "url": rawURL},
	}, nil
}

// WithRisk overrides the default method classification.
// A GET that carries a probe payload is active, not a passive read.
func (a Action) WithRisk(risk policy.Risk) Action {
	a.Risk = risk
	if risk == policy.RiskPassive {
		a.Phase = "recon"
		return a
	}
	if a.Phase == "" || a.Phase == "recon" {
		a.Phase = "exploitation"
	}
	return a
}
