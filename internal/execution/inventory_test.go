package execution

import "testing"

func TestExecutionPathInventory(t *testing.T) {
	required := []string{
		"llm.execute_command",
		"llm.visual_crawl",
		"fuzzclient",
		"cors.raw_client",
		"specialist.raw_clients",
		"schedule",
		"cicd",
		"docker.shared_sandbox",
		"oob.callback",
	}
	paths := ExecutionPaths()
	seen := map[string]Path{}
	for _, path := range paths {
		if path.ID == "" || path.Entry == "" || path.ScopeToday == "" || path.V2Status == "" {
			t.Fatalf("incomplete path: %+v", path)
		}
		seen[path.ID] = path
	}
	for _, id := range required {
		if _, ok := seen[id]; !ok {
			t.Errorf("inventory missing %s", id)
		}
	}
}
