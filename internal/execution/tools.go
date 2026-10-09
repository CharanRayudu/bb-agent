package execution

import (
	"encoding/json"
	"net"
	"strings"
)

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
