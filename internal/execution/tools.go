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
	if isFilename(value) {
		return false
	}
	if strings.Contains(value, ":") && !strings.Contains(value, "://") {
		host, _, ok := strings.Cut(value, ":")
		return ok && looksLikeHost(host)
	}
	return strings.Contains(value, ".") || net.ParseIP(value) != nil
}

func isFilename(value string) bool {
	if strings.Contains(value, "://") {
		return false
	}
	if strings.ContainsAny(value, `/\`) {
		return true
	}
	ext := strings.ToLower(strings.TrimPrefix(pathExt(value), "."))
	switch ext {
	case "txt", "xml", "json", "jsonl", "csv", "html", "htm", "md", "log", "out",
		"gnmap", "nmap", "sarif", "conf", "cfg", "yaml", "yml", "lst", "pdf",
		"png", "jpg", "jpeg", "gif", "har", "css", "js", "map", "zip", "gz", "tar":
		return true
	default:
		return false
	}
}

func pathExt(value string) string {
	slash := strings.LastIndexAny(value, `/\`)
	base := value
	if slash >= 0 {
		base = value[slash+1:]
	}
	dot := strings.LastIndex(base, ".")
	if dot < 0 {
		return ""
	}
	return base[dot:]
}
