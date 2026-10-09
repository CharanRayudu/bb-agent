package execution

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/bb-agent/mirage/internal/policy"
)

const (
	flagBool    = "bool"
	flagSkip    = "skip"
	flagTarget  = "target"
	flagFile    = "file"
	flagPorts   = "ports"
	flagRequest = "request"
)

// parseScanEndpoints reads a scanner argv and returns the hosts and ports
// that the tool will actually contact. Output files, wordlists, and other
// non-targets are ignored. Target-list files are read and authorized.
func parseScanEndpoints(tool string, args []string) ([]policy.Target, error) {
	flags := flagTable(tool)
	var ports []int
	var targets []string
	var listFiles []string
	var requestFiles []string
	udp := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			targets = append(targets, destinationTokens(args[i+1:])...)
			break
		}
		if arg == "-iR" || arg == "--randomize-hosts" {
			return nil, fmt.Errorf("%s does not accept random or unknown targets", tool)
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			name, inline := splitFlag(arg, flags)
			if name == "-sU" {
				udp = true
			}
			kind := flags[name]
			value := inline
			if consumesValue(kind) || kind == flagRequest {
				if value == "" {
					if i+1 >= len(args) {
						return nil, fmt.Errorf("%s requires a value", name)
					}
					i++
					value = args[i]
				}
			}
			switch kind {
			case flagPorts:
				parsed, err := parsePortSpec(value)
				if err != nil {
					return nil, err
				}
				ports = append(ports, parsed...)
			case flagTarget:
				targets = append(targets, value)
			case flagFile:
				listFiles = append(listFiles, value)
			case flagRequest:
				requestFiles = append(requestFiles, value)
			}
			continue
		}
		if isDestinationToken(arg) {
			targets = append(targets, arg)
		}
	}
	for _, file := range listFiles {
		lines, err := readTargetLines(file)
		if err != nil {
			return nil, err
		}
		targets = append(targets, lines...)
	}
	for _, file := range requestFiles {
		lines, err := readRequestTargets(file)
		if err != nil {
			return nil, err
		}
		targets = append(targets, lines...)
	}
	if len(ports) > 64 {
		return nil, fmt.Errorf("port list has %d ports; name at most 64 authorized ports", len(ports))
	}
	return materializeEndpoints(tool, targets, ports, udp)
}

func flagTable(tool string) map[string]string {
	flags := map[string]string{}
	set := func(kind string, names ...string) {
		for _, name := range names {
			flags[name] = kind
		}
	}
	switch tool {
	case "nmap", "masscan", "naabu":
		set(flagPorts, "-p", "--ports")
		set(flagFile, "-iL", "--includefile")
		set(flagSkip, "-oN", "-oX", "-oG", "-oA", "-oS", "-oL", "-oJ", "--exclude", "--excludefile", "--script", "--script-args", "--stylesheet", "--dns-servers", "-S", "-e", "--data-length", "--max-retries", "--host-timeout", "--min-rate", "--max-rate", "-g", "--source-port", "-o", "--output")
		set(flagBool, "-Pn", "-n", "-A", "-O", "-sS", "-sT", "-sU", "-sV", "-sC", "-v", "-d", "-F", "-r", "--open", "-6", "--reason")
		set(flagTarget, "-host", "--host")
	case "httpx":
		set(flagTarget, "-u", "-target", "--target")
		set(flagFile, "-l", "-list")
		set(flagPorts, "-p", "-ports", "--ports")
		set(flagSkip, "-o", "-output", "-path", "-H", "-header")
		set(flagBool, "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects")
	case "curl":
		set(flagTarget, "--url")
		set(flagSkip, "-o", "--output", "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-H", "--header", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-x", "--proxy", "-w", "--write-out", "-T", "--upload-file", "-u", "--user", "-X", "--request", "-m", "--max-time", "--connect-timeout", "--retry", "--retry-delay")
		set(flagBool, "-L", "-k", "-s", "-S", "-v", "-I", "-G", "-f", "--path-as-is", "--compressed")
	case "nuclei":
		set(flagTarget, "-u", "-target")
		set(flagFile, "-l", "-list")
		set(flagSkip, "-t", "-templates", "-o", "-output", "-H", "-header", "-proxy", "-timeout", "-rate-limit", "-rl", "-c", "-severity", "-tags", "-et", "-config", "-jsonl-export", "-markdown-export", "-sarif-export", "-json-export")
		set(flagBool, "-silent", "-nc", "-j", "-jsonl", "-v", "-debug", "-irr")
	case "ffuf":
		set(flagTarget, "-u")
		set(flagSkip, "-w", "-o", "-of", "-H", "-X", "-d", "-x", "-t", "-p", "-mc", "-fc", "-fs", "-fw", "-fl", "-rate", "-timeout", "-config", "-request", "-recursion-depth")
		set(flagBool, "-ac", "-v", "-s", "-noninteractive")
	case "sqlmap":
		set(flagTarget, "-u", "--url")
		set(flagFile, "-m")
		set(flagRequest, "-r", "--request")
		set(flagSkip, "--data", "--cookie", "--headers", "--proxy", "--user-agent", "--level", "--risk", "--tamper", "--output-dir", "-D", "-T", "-C", "--threads", "--delay", "--technique", "--dbms", "--user", "--password")
		set(flagBool, "-o", "--batch", "--dbs", "--tables", "--random-agent", "--forms", "--flush-session")
	case "gobuster":
		set(flagTarget, "-u", "--url")
		set(flagSkip, "-w", "--wordlist", "-o", "--output", "-t", "-x", "-s", "-b", "-c", "-H", "-p", "--proxy")
		set(flagBool, "-q", "-k", "-r", "--no-error")
	case "katana", "hakrawler":
		set(flagTarget, "-u")
		set(flagFile, "-list")
		set(flagSkip, "-o", "-d", "-H", "-proxy", "-timeout", "-c")
		set(flagBool, "-silent", "-v")
	case "feroxbuster", "dirsearch":
		set(flagTarget, "-u", "--url")
		set(flagSkip, "-o", "--output", "-w", "--wordlist", "-x", "-H", "-t", "--timeout")
		set(flagBool, "-q", "-k", "--silent")
	case "dalfox", "ghauri", "commix", "tplmap", "crlfuzz":
		set(flagTarget, "-u", "--url")
		set(flagSkip, "-o", "--output", "-b", "--cookie", "-H", "--header", "--data", "-d", "-p", "--param")
		set(flagBool, "--silence", "--no-color", "--batch")
	default:
		set(flagTarget, "-u", "--url", "-d", "--domain", "-host")
		set(flagFile, "-l", "-list", "-iL")
		set(flagSkip, "-o", "--output", "-w", "--wordlist", "-H", "--header")
		set(flagBool, "-silent", "-v")
	}
	return flags
}

func consumesValue(kind string) bool {
	switch kind {
	case flagSkip, flagTarget, flagFile, flagPorts:
		return true
	default:
		return false
	}
}

func splitFlag(arg string, flags map[string]string) (string, string) {
	if strings.HasPrefix(arg, "--") {
		if name, value, ok := strings.Cut(arg, "="); ok {
			return name, value
		}
		return arg, ""
	}
	if strings.HasPrefix(arg, "-") {
		best := ""
		for name := range flags {
			if strings.HasPrefix(arg, name) && len(name) > len(best) {
				best = name
			}
		}
		if best != "" && len(arg) == len(best) {
			return best, ""
		}
		if best != "" && consumesValue(flags[best]) && len(arg) > len(best) {
			return best, arg[len(best):]
		}
	}
	return arg, ""
}

func destinationTokens(args []string) []string {
	var out []string
	for _, arg := range args {
		if isDestinationToken(arg) {
			out = append(out, arg)
		}
	}
	return out
}

func isDestinationToken(arg string) bool {
	arg = strings.Trim(arg, `"'`)
	if arg == "" || isFilename(arg) {
		return false
	}
	if strings.Contains(arg, "://") || looksLikeHost(arg) {
		return true
	}
	return false
}

func materializeEndpoints(tool string, targets []string, ports []int, udp bool) ([]policy.Target, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("security tool %s is missing a destination", tool)
	}
	portScanner := tool == "nmap" || tool == "masscan" || tool == "naabu"
	transport := "tcp"
	if udp {
		transport = "udp"
	}
	var out []policy.Target
	for _, raw := range targets {
		host, scheme, port, ok := splitTarget(raw)
		if !ok || host == "" {
			continue
		}
		switch {
		case portScanner:
			use := ports
			if len(use) == 0 && port > 0 {
				use = []int{port}
			}
			if len(use) == 0 {
				return nil, fmt.Errorf("%s requires -p with the authorized ports, or a target that already includes a port", tool)
			}
			for _, p := range use {
				out = append(out, policy.Target{Scheme: transport, Host: host, Port: p})
			}
		case tool == "httpx" && len(ports) > 0:
			if scheme == "" {
				scheme = "http"
			}
			for _, p := range ports {
				out = append(out, policy.Target{Scheme: scheme, Host: host, Port: p})
			}
		default:
			if scheme == "" {
				scheme = "http"
			}
			out = append(out, policy.Target{Scheme: scheme, Host: host, Port: port})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("security tool %s is missing a destination", tool)
	}
	return dedupeTargets(out), nil
}

func splitTarget(raw string) (string, string, int, bool) {
	raw = strings.Trim(raw, `"'`)
	if raw == "" || isFilename(raw) {
		return "", "", 0, false
	}
	if strings.Contains(raw, "://") {
		cleaned := raw
		if i := strings.IndexAny(raw, " \t'\"<>"); i > 0 && strings.Contains(raw[:i], "://") {
			cleaned = raw[:i]
		}
		parsed, err := url.Parse(cleaned)
		if err != nil || parsed.Hostname() == "" {
			return "", "", 0, false
		}
		port := 0
		if parsed.Port() != "" {
			port, _ = strconv.Atoi(parsed.Port())
		}
		return strings.ToLower(parsed.Hostname()), strings.ToLower(parsed.Scheme), port, true
	}
	if host, portText, err := net.SplitHostPort(raw); err == nil {
		port, conv := strconv.Atoi(portText)
		if conv == nil && looksLikeHost(host) {
			return strings.ToLower(host), "", port, true
		}
	}
	if looksLikeHost(raw) {
		return strings.ToLower(raw), "", 0, true
	}
	return "", "", 0, false
}

func parsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "-" || spec == "0-" || strings.EqualFold(spec, "all") {
		return nil, fmt.Errorf("port list is unbounded; name the authorized ports")
	}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			startText, endText, _ := strings.Cut(part, "-")
			start, err1 := strconv.Atoi(startText)
			end, err2 := strconv.Atoi(endText)
			if err1 != nil || err2 != nil || start <= 0 || end > 65535 || end < start {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if end-start > 64 {
				return nil, fmt.Errorf("port range %s is wider than 64 ports; name the authorized ports", part)
			}
			for port := start; port <= end; port++ {
				out = append(out, port)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		out = append(out, port)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port list")
	}
	return out, nil
}

func readRequestTargets(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read request file %s: %w", path, err)
	}
	text := string(body)
	var targets []string
	for _, match := range commandURLRe.FindAllString(text, -1) {
		targets = append(targets, match)
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			host := strings.TrimSpace(line[5:])
			if host != "" {
				targets = append(targets, host)
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("request file %s does not contain a host", path)
	}
	return targets, nil
}

func readTargetLines(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("target list path is missing")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read target list %s: %w", path, err)
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("target list %s is larger than 1MB", path)
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("target list %s is empty", path)
	}
	return lines, nil
}

func dedupeTargets(in []policy.Target) []policy.Target {
	seen := map[string]bool{}
	var out []policy.Target
	for _, target := range in {
		key := strings.ToLower(target.Scheme) + "|" + strings.ToLower(target.Host) + "|" + strconv.Itoa(target.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	return out
}
