package execution

import (
	"os"
	"path/filepath"
	"strings"
)

const WorkspaceMount = "/workspace"

// WorkspaceRoot is the host directory that holds one folder per flow.
func WorkspaceRoot() string {
	if root := strings.TrimSpace(os.Getenv("MIRAGE_WORKSPACE_ROOT")); root != "" {
		return root
	}
	return filepath.Join("data", "workspaces")
}

// EnsureWorkspace creates the directory the API process writes into.
func EnsureWorkspace(flowID string) (string, error) {
	dir := filepath.Join(WorkspaceRoot(), safeWorkspaceID(flowID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir, nil
	}
	return abs, nil
}

// WorkspaceBindSource is the path the Docker daemon mounts into a flow container.
// When the API itself runs in a container, MIRAGE_WORKSPACE_HOST_ROOT is the
// same directory as seen from the host. Otherwise it matches EnsureWorkspace.
func WorkspaceBindSource(flowID string) (string, error) {
	if _, err := EnsureWorkspace(flowID); err != nil {
		return "", err
	}
	hostRoot := strings.TrimSpace(os.Getenv("MIRAGE_WORKSPACE_HOST_ROOT"))
	if hostRoot == "" {
		return EnsureWorkspace(flowID)
	}
	return filepath.Join(hostRoot, safeWorkspaceID(flowID)), nil
}

// FlowWorkspaceName is the per-flow directory name under the workspace root.
func FlowWorkspaceName(flowID string) string {
	return safeWorkspaceID(flowID)
}

// WorkspaceBindFromMount joins a Docker-daemon mount source with the flow directory.
// mountSource must be the path the daemon already uses for the API workspace volume.
func WorkspaceBindFromMount(mountSource, flowID string) string {
	return filepath.Join(mountSource, safeWorkspaceID(flowID))
}

// RewriteWorkspaceOutputs moves relative scanner output paths into the
// mounted workspace so the API process can read evidence after the tool exits.
func RewriteWorkspaceOutputs(argv []string) []string {
	if len(argv) == 0 {
		return argv
	}
	out := append([]string{}, argv...)
	flags := map[string]bool{
		"-o": true, "--output": true, "-oN": true, "-oX": true, "-oG": true, "-oA": true,
		"-oL": true, "-oJ": true, "--output-dir": true,
	}
	for i := 0; i < len(out); i++ {
		name, inline := splitOutputFlag(out[i], flags)
		if !flags[name] {
			continue
		}
		if inline != "" {
			out[i] = name + relocateOutput(inline)
			continue
		}
		if i+1 < len(out) {
			out[i+1] = relocateOutput(out[i+1])
			i++
		}
	}
	return out
}

func splitOutputFlag(arg string, flags map[string]bool) (string, string) {
	if strings.HasPrefix(arg, "--") {
		if name, value, ok := strings.Cut(arg, "="); ok && flags[name] {
			return name, value
		}
		return arg, ""
	}
	best := ""
	for name := range flags {
		if strings.HasPrefix(arg, name) && len(name) > len(best) {
			best = name
		}
	}
	if best != "" && len(arg) > len(best) {
		return best, arg[len(best):]
	}
	return arg, ""
}

func relocateOutput(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || strings.Contains(path, "://") || strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) || filepath.IsAbs(path) || strings.HasPrefix(path, WorkspaceMount+"/") || path == WorkspaceMount {
		return path
	}
	return WorkspaceMount + "/" + strings.TrimPrefix(filepath.ToSlash(path), "./")
}

func safeWorkspaceID(flowID string) string {
	var buf strings.Builder
	for _, r := range flowID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			buf.WriteRune(r)
		}
		if buf.Len() == 64 {
			break
		}
	}
	if buf.Len() == 0 {
		return "flow"
	}
	return buf.String()
}
