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
			ID:          "gpt-5.4",
			Name:        "gpt-5.4",
			Description: "Latest frontier agentic coding model.",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-5.3-codex",
			Name:        "gpt-5.3-codex",
			Description: "Latest frontier agentic coding model.",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.2-codex",
			Name:        "gpt-5.2-codex",
			Description: "Frontier agentic coding model.",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.1-codex-max",
			Name:        "gpt-5.1-codex-max",
			Description: "Codex-optimized flagship for deep and fast reasoning.",
			Category:    "Coding",
		},
		{
			ID:          "gpt-5.2",
			Name:        "gpt-5.2",
			Description: "Latest frontier model with improvements across knowledge, reasoning and coding",
			Category:    "General",
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
