package execution

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

// knownSecurityTools are binaries the engagement may run as an argv array.
// The name is taken from a structured tool field, never from the first token
// of a shell string. Anything else stays an unrestricted shell command.
var knownSecurityTools = map[string]policy.Risk{
	"nuclei":      policy.RiskExploitation,
	"sqlmap":      policy.RiskExploitation,
	"dalfox":      policy.RiskExploitation,
	"ghauri":      policy.RiskExploitation,
	"commix":      policy.RiskExploitation,
	"tplmap":      policy.RiskExploitation,
	"crlfuzz":     policy.RiskExploitation,
	"nmap":        policy.RiskActive,
	"masscan":     policy.RiskActive,
	"naabu":       policy.RiskActive,
	"ffuf":        policy.RiskActive,
	"feroxbuster": policy.RiskActive,
	"gobuster":    policy.RiskActive,
	"dirsearch":   policy.RiskActive,
	"arjun":       policy.RiskActive,
	"curl":        policy.RiskActive,
	"httpx":       policy.RiskActive,
	"katana":      policy.RiskActive,
	"hakrawler":   policy.RiskActive,
	"gau":         policy.RiskPassive,
	"waybackurls": policy.RiskPassive,
	"subfinder":   policy.RiskPassive,
	"amass":       policy.RiskPassive,
	"puredns":     policy.RiskPassive,
}

// SecurityToolAction classifies a structured {tool, args[]} invocation.
// A shell-shaped command string is not accepted here.
func SecurityToolAction(flowID, actor string, raw json.RawMessage) Action {
	action := shellAction(flowID, actor, raw)
	action.ToolID = "run_security_tool"
	tool, argv, timeout, endpoints, err := parseSecurityArgv(raw)
	if err != nil {
		action.Shell = false
		action.Arguments["reject"] = err.Error()
		return action
	}
	risk := knownSecurityTools[tool]
	action.Shell = false
	action.ActionType = "tool." + tool
	action.SkillID = "tool." + tool
	action.ToolID = tool
	action.Risk = risk
	action.Phase = "exploitation"
	if risk == policy.RiskPassive {
		action.Phase = "recon"
	}
	action.Timeout = time.Duration(timeout) * time.Second
	action.IdempotencyKey = flowID + ":" + tool + ":" + hashArgs(raw)
	action.Digest = Digest(tool + "\n" + strings.Join(argv, "\n"))
	action.Arguments = map[string]string{"tool": tool}
	applyEndpoints(&action, endpoints)
	return action
}

// ParseSecurityArgv validates a run_security_tool payload and returns the
// argv array that must be executed without a shell.
func ParseSecurityArgv(raw json.RawMessage) ([]string, int, error) {
	tool, extra, timeout, _, err := parseSecurityArgv(raw)
	if err != nil {
		return nil, 0, err
	}
	argv := make([]string, 0, 1+len(extra))
	argv = append(argv, tool)
	argv = append(argv, extra...)
	return argv, timeout, nil
}

func parseSecurityArgv(raw json.RawMessage) (string, []string, int, []policy.Target, error) {
	var params struct {
		Tool    string   `json:"tool"`
		Args    []string `json:"args"`
		Timeout int      `json:"timeout"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return "", nil, 0, nil, fmt.Errorf("run_security_tool arguments must be a tool name and an args array")
	}
	tool, err := canonicalTool(params.Tool)
	if err != nil {
		return "", nil, 0, nil, err
	}
	if _, ok := knownSecurityTools[tool]; !ok {
		return "", nil, 0, nil, fmt.Errorf("unknown security tool %q", tool)
	}
	timeout := params.Timeout
	if timeout <= 0 {
		timeout = 300
	}
	if timeout > 1800 {
		timeout = 1800
	}
	for _, arg := range params.Args {
		if strings.ContainsRune(arg, 0) {
			return "", nil, 0, nil, fmt.Errorf("security tool arguments cannot contain NUL")
		}
	}
	endpoints, err := parseScanEndpoints(tool, params.Args)
	if err != nil {
		return "", nil, 0, nil, err
	}
	return tool, params.Args, timeout, endpoints, nil
}

func applyEndpoints(action *Action, endpoints []policy.Target) {
	if action == nil || len(endpoints) == 0 {
		return
	}
	action.Endpoints = endpoints
	action.Scheme = endpoints[0].Scheme
	action.Host = endpoints[0].Host
	action.Port = endpoints[0].Port
}

func canonicalTool(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("security tool name is empty")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("security tool name must not be a path")
	}
	base := strings.ToLower(strings.TrimSuffix(path.Base(name), ".exe"))
	if base == "" || strings.ContainsAny(base, `;&|$<>(){}`) {
		return "", fmt.Errorf("security tool name is not a single executable")
	}
	return base, nil
}

func argvDestinations(argv []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.Trim(value, `"'`)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, arg := range argv {
		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, "://") {
			continue
		}
		for _, match := range commandURLRe.FindAllString(arg, -1) {
			add(match)
		}
		if looksLikeHost(arg) {
			add(arg)
		}
	}
	return out
}

// AppendProxyArg inserts the flow proxy flag for HTTP tools that honor one.
// Tools that open raw sockets are returned unchanged; their destinations were
// already authorized, and the shared sandbox network is a separate limit.
func AppendProxyArg(argv []string, proxyURL string) []string {
	if len(argv) == 0 || proxyURL == "" {
		return argv
	}
	tool, err := canonicalTool(argv[0])
	if err != nil {
		return argv
	}
	var flag []string
	switch tool {
	case "curl":
		flag = []string{"--proxy", proxyURL}
	case "nuclei", "katana":
		flag = []string{"-proxy", proxyURL}
	case "httpx":
		flag = []string{"-http-proxy", proxyURL}
	case "ffuf":
		flag = []string{"-x", proxyURL}
	case "sqlmap":
		flag = []string{"--proxy", proxyURL}
	case "gobuster":
		flag = []string{"--proxy", proxyURL}
	default:
		return argv
	}
	out := make([]string, 0, len(argv)+len(flag))
	out = append(out, argv[0])
	out = append(out, flag...)
	out = append(out, argv[1:]...)
	return out
}

func shellAction(flowID, actor string, raw json.RawMessage) Action {
	command := extractCommand(string(raw))
	return Action{
		FlowID:         flowID,
		EngagementID:   flowID,
		ActorID:        actor,
		ActionType:     "shell.command",
		Risk:           policy.RiskExploitation,
		Phase:          "exploitation",
		Shell:          true,
		SkillID:        "shell.command",
		ToolID:         "execute_command",
		IdempotencyKey: flowID + ":shell:" + hashArgs([]byte(command)),
		Digest:         Digest(command),
		Arguments:      map[string]string{"command": command},
	}
}
