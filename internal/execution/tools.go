package execution

import (
	"encoding/json"
	"net"
	"os"
	"path"
	"strings"

	"github.com/bb-agent/mirage/internal/policy"
)

// knownSecurityTools may run inside scope without the unrestricted-shell grant.
// Anything else remains an arbitrary shell command.
var knownSecurityTools = map[string]policy.Risk{
	"nuclei":      policy.RiskExploitation,
	"nmap":        policy.RiskActive,
	"ffuf":        policy.RiskActive,
	"curl":        policy.RiskActive,
	"sqlmap":      policy.RiskExploitation,
	"httpx":       policy.RiskPassive,
	"katana":      policy.RiskPassive,
	"gobuster":    policy.RiskActive,
	"gau":         policy.RiskPassive,
	"waybackurls": policy.RiskPassive,
}

func hasShellMetacharacters(cmd string) bool {
	operators := []string{";", "&&", "||", "|", ">", "<", "`", "$("}
	for _, op := range operators {
		if strings.Contains(cmd, op) {
			return true
		}
	}
	return false
}

func hasDangerousFlags(tool string, argv []string) bool {
	for _, arg := range argv[1:] {
		argLower := strings.ToLower(arg)
		if tool == "sqlmap" && (argLower == "--os-shell" || argLower == "--os-cmd" || argLower == "--os-pwn" || argLower == "--file-read" || argLower == "--file-write") {
			return true
		}
		if tool == "curl" && (strings.HasPrefix(argLower, "file://") || argLower == "-o" || argLower == "--output" || argLower == "-K" || argLower == "--config") {
			return true
		}
		if tool == "nmap" && (strings.HasPrefix(argLower, "--script") || argLower == "--interactive") {
			return true
		}
	}
	return false
}

func classifyCommand(flowID, raw string) Action {
	command := extractCommand(raw)
	action := Action{
		FlowID:         flowID,
		EngagementID:   flowID,
		ActionType:     "shell.command",
		Risk:           policy.RiskExploitation,
		Phase:          "exploitation",
		Shell:          true,
		SkillID:        "shell.command",
		ToolID:         "execute_command",
		IdempotencyKey: flowID + ":shell:" + hashArgs([]byte(command)),
		Arguments:      map[string]string{"command": command},
	}

	argv := splitArgs(command)
	if len(argv) == 0 {
		return action
	}

	tool := strings.ToLower(strings.TrimSuffix(path.Base(strings.Trim(argv[0], `"'`)), ".exe"))
	risk, known := knownSecurityTools[tool]

	// Shell metacharacters or dangerous tool flags force action.Shell = true
	if hasShellMetacharacters(command) || hasDangerousFlags(tool, argv) {
		targets := commandDestinations(command, argv)
		applyDestinationList(&action, targets)
		return action
	}

	targets := commandDestinations(command, argv)
	if !known {
		applyDestinationList(&action, targets)
		return action
	}
	if len(targets) == 0 {
		action.Shell = true
		action.Arguments["reason"] = "known tool missing a destination"
		return action
	}
	action.Shell = false
	action.ActionType = "tool." + tool
	action.SkillID = "tool." + tool
	action.ToolID = tool
	action.Risk = risk
	if risk == policy.RiskPassive {
		action.Phase = "recon"
	}
	action.IdempotencyKey = flowID + ":" + tool + ":" + hashArgs([]byte(command))
	applyDestinationList(&action, targets)
	return action
}

func extractCommand(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		var params struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal([]byte(raw), &params); err == nil && params.Command != "" {
			return params.Command
		}
	}
	return raw
}

func commandDestinations(command string, argv []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.Trim(value, `"'`)
		if value == "" || seen[value] {
			return
		}
		if !strings.Contains(value, "://") && !looksLikeHost(value) {
			return
		}
		seen[value] = true
		out = append(out, value)
	}

	for _, match := range commandURLRe.FindAllString(command, -1) {
		add(match)
	}

	// Parse file argument options like -iL (nmap/nuclei) and -r (sqlmap)
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		var filePath string
		if arg == "-iL" || arg == "-l" || arg == "-r" || arg == "-list" {
			if i+1 < len(argv) {
				filePath = argv[i+1]
				i++
			}
		} else if strings.HasPrefix(arg, "-iL=") || strings.HasPrefix(arg, "-l=") || strings.HasPrefix(arg, "-r=") || strings.HasPrefix(arg, "-list=") {
			_, filePath, _ = strings.Cut(arg, "=")
		}

		if filePath != "" {
			if content, err := os.ReadFile(filePath); err == nil {
				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					// Extract Host header from raw HTTP request files (-r)
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						_, hval, _ := strings.Cut(line, ":")
						add(strings.TrimSpace(hval))
					} else if match := commandURLRe.FindString(line); match != "" {
						add(match)
					} else if looksLikeHost(line) {
						add(line)
					}
				}
			}
		}

		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, "://") {
			continue
		}
		add(arg)
	}
	return out
}

func applyDestinationList(action *Action, targets []string) {
	if len(targets) == 0 {
		return
	}
	applyFirstURL(action, normalizeTarget(targets[0]))
	for _, target := range targets[1:] {
		action.ExtraTargets = append(action.ExtraTargets, normalizeTarget(target))
	}
}

func normalizeTarget(value string) string {
	if strings.Contains(value, "://") {
		return value
	}
	return "http://" + value
}

func looksLikeHost(value string) bool {
	value = strings.Trim(value, `"'`)
	if value == "" || strings.ContainsAny(value, " \t/?#") {
		return false
	}
	if strings.Contains(value, ":") && !strings.Contains(value, "://") {
		host, _, ok := strings.Cut(value, ":")
		return ok && looksLikeHost(host)
	}
	return strings.Contains(value, ".") || net.ParseIP(value) != nil
}

func splitArgs(command string) []string {
	var args []string
	var current strings.Builder
	quote := byte(0)
	for i := 0; i < len(command); i++ {
		ch := command[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteByte(ch)
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == ' ' || ch == '\t':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
