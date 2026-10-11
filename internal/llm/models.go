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
// when authenticated via ChatGPT OAuth. Retired ids stay listed so the UI can
// show remapping guidance, but they are marked in the description.
func GetAvailableModels(codexHome string) []CodexModel {
	currentModel := readCurrentModel(codexHome)

	models := []CodexModel{
		{
			ID:          "gpt-6.1-sol",
			Name:        "gpt-6.1-sol",
			Description: "Current recommended Codex ChatGPT model for complex agent work.",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-6-sol",
			Name:        "gpt-6-sol",
			Description: "Codex ChatGPT model for repeated long-running work.",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-6-luna",
			Name:        "gpt-6-luna",
			Description: "Efficient Codex ChatGPT model for focused high-volume tasks.",
			Category:    "Recommended",
		},
		{
			ID:          "gpt-6-astra",
			Name:        "gpt-6-astra",
			Description: "Highest-capability Codex ChatGPT model when available to the account.",
			Category:    "Advanced",
		},
		{
			ID:          "gpt-4o",
			Name:        "gpt-4o",
			Description: "OpenAI API chat model. Use with MIRAGE_LLM_PROVIDER=api_key.",
			Category:    "API key",
		},
		{
			ID:          "gpt-5.3-codex",
			Name:        "gpt-5.3-codex",
			Description: "Retired for Codex ChatGPT sign-in. Mirage remaps this to gpt-6.1-sol.",
			Category:    "Retired",
		},
		{
			ID:          "gpt-5.4",
			Name:        "gpt-5.4",
			Description: "Retired for Codex ChatGPT sign-in. Mirage remaps this to gpt-6.1-sol.",
			Category:    "Retired",
		},
	}

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
