package execution

import (
	"fmt"
	"io"
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

// StageWorkspaceInputs copies target-list and raw-request files into the flow
// workspace and rewrites those arguments to /workspace paths. Output flags are
// rewritten the same way. Other arguments are left unchanged.
func StageWorkspaceInputs(flowID string, argv []string) ([]string, error) {
	if len(argv) == 0 {
		return argv, nil
	}
	out := append([]string{}, argv...)
	tool, err := canonicalTool(out[0])
	if err != nil {
		return RewriteWorkspaceOutputs(out), nil
	}
	workspace, err := EnsureWorkspace(flowID)
	if err != nil {
		return nil, err
	}
	flags := flagTable(tool)
	for i := 0; i < len(out); i++ {
		arg := out[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		name, inline := splitFlag(arg, flags)
		kind := flags[name]
		if kind != flagFile && kind != flagRequest {
			continue
		}
		if inline != "" {
			container, err := stageOneFile(workspace, inline)
			if err != nil {
				return nil, err
			}
			out[i] = name + container
			continue
		}
		if i+1 >= len(out) {
			return nil, fmt.Errorf("%s requires a file path", name)
		}
		container, err := stageOneFile(workspace, out[i+1])
		if err != nil {
			return nil, err
		}
		out[i+1] = container
		i++
	}
	return RewriteWorkspaceOutputs(out), nil
}

func stageOneFile(workspace, raw string) (string, error) {
	host, err := locateToolFile(workspace, raw)
	if err != nil {
		return "", err
	}
	rel, relErr := filepath.Rel(workspace, host)
	if relErr == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
		return WorkspaceMount + "/" + filepath.ToSlash(rel), nil
	}
	base := filepath.Base(host)
	if base == "." || base == string(filepath.Separator) || strings.Contains(base, "..") {
		return "", fmt.Errorf("tool file %s has no usable name", raw)
	}
	dest := filepath.Join(workspace, base)
	if filepath.Clean(host) != filepath.Clean(dest) {
		if err := copyToolFile(host, dest); err != nil {
			return "", err
		}
	}
	return WorkspaceMount + "/" + base, nil
}

func locateToolFile(workspace, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	var candidates []string
	if strings.HasPrefix(raw, WorkspaceMount+"/") {
		candidates = append(candidates, filepath.Join(workspace, strings.TrimPrefix(raw, WorkspaceMount+"/")))
	}
	candidates = append(candidates, raw)
	if !filepath.IsAbs(raw) && !strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, `\`) {
		candidates = append(candidates, filepath.Join(workspace, filepath.FromSlash(raw)))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("cannot read tool file %s", raw)
}

func copyToolFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, io.LimitReader(in, 1<<20+1)); err != nil {
		return err
	}
	return nil
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
