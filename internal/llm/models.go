package llm

import (
	"os"
	"path/filepath"
	"strings"
)

// CodexModel represents an available model in the Codex CLI ecosystem
type CodexModel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Current     bool   `json:"current"`
}

// GetAvailableModels returns the list of models available through Codex CLI
// These are the models supported when authenticated via ChatGPT OAuth
func GetAvailableModels(codexHome string) []CodexModel {
	currentModel := readCurrentModel(codexHome)

	models := []CodexModel{
		{
			ID:          "gpt-5.3-codex",
			Name:        "GPT-5.3 Codex",
			Description: "Most capable agentic coding model — strong reasoning + professional knowledge",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-5.3-codex-spark",
			Name:        "GPT-5.3 Codex Spark",
			Description: "Near-instant real-time coding iterations (Pro only)",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-5.2-codex",
			Name:        "GPT-5.2 Codex",
			Description: "Advanced coding model for real-world engineering tasks",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.1-codex-max",
			Name:        "GPT-5.1 Codex Max",
			Description: "Optimized for long-running, project-scale work",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.1-codex-mini",
			Name:        "GPT-5.1 Codex Mini",
			Description: "Fast and cost-effective for simpler tasks",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.2",
			Name:        "GPT-5.2",
			Description: "General-purpose agentic reasoning model",
			Category:    "General",
		},
		{
			ID:          "gpt-5.1",
			Name:        "GPT-5.1",
			Description: "General-purpose reasoning model",
			Category:    "General",
		},
		{
			ID:          "gpt-5",
			Name:        "GPT-5",
			Description: "Base reasoning model",
			Category:    "General",
		},
		{
			ID:          "gpt-4o",
			Name:        "GPT-4o",
			Description: "Multimodal flagship model — fast and versatile",
			Category:    "Legacy",
		},
		{
			ID:          "o3",
			Name:        "o3",
			Description: "Advanced reasoning model with chain-of-thought",
			Category:    "Reasoning",
		},
		{
			ID:          "o4-mini",
			Name:        "o4-mini",
			Description: "Fast reasoning model — great balance of speed and capability",
			Category:    "Reasoning",
		},
	}

	// Mark which model is currently selected in the user's config
	for i := range models {
		if models[i].ID == currentModel {
			models[i].Current = true
		}
	}

	return models
}

// readCurrentModel reads the model setting from ~/.codex/config.toml
func readCurrentModel(codexHome string) string {
	if codexHome == "" {
		codexHome = defaultCodexHome()
	}

	configPath := filepath.Join(codexHome, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	// Simple TOML parsing — look for the model = "..." line
	// Only match top-level model key (not inside a [section])
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inSection = true
			continue
		}
		if !inSection && strings.HasPrefix(line, "model") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"'")
				return val
			}
		}
	}
	return ""
}
