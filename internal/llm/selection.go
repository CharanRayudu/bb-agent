package llm

import (
	"fmt"
	"strings"
)

// ProviderPreference selects how Mirage authenticates to a generative model.
// auto prefers Codex OAuth when a cached login exists, otherwise an API key.
const (
	ProviderAuto   = "auto"
	ProviderCodex  = "codex"
	ProviderAPIKey = "api_key"
)

// Selection describes the generative provider that will run a scan.
type Selection struct {
	Preference  string
	AuthMode    AuthMode
	Model       string
	Requested   string
	Remapped    bool
	RemapReason string
	Source      string
}

func (s Selection) Status() string {
	msg := fmt.Sprintf("llm provider %s auth=%s model=%s", s.Source, s.AuthMode, s.Model)
	if s.Remapped {
		msg += fmt.Sprintf(" (requested %s; %s)", s.Requested, s.RemapReason)
	}
	return msg
}

// SelectionInput is the operator configuration used to pick a provider.
type SelectionInput struct {
	Preference     string
	CodexHome      string
	APIKey         string
	Model          string
	FallbackModel  string
	Temperature    float64
	CodexAvailable bool
}

// DefaultCodexModel is the ChatGPT-sign-in model Mirage uses when the
// configured model is known to be retired for Codex OAuth.
const DefaultCodexModel = "gpt-6.1-sol"

func isRetiredCodexChatGPTModel(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "gpt-5.3-codex", "gpt-5.3-codex-spark", "gpt-5.2-codex", "gpt-5.2",
		"gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.1-codex-max", "gpt-4o", "gpt-4o-mini":
		return true
	default:
		return false
	}
}

// ResolveModelForAuth remaps retired Codex ChatGPT models. API-key auth keeps
// the requested model unless it is empty. For Codex OAuth, preference order is
// explicit fallback, then ~/.codex/config.toml, then DefaultCodexModel.
func ResolveModelForAuth(mode AuthMode, requested, fallback, codexHome string) (string, bool, string) {
	model := strings.TrimSpace(requested)
	if model == "" {
		if mode == AuthModeCodexOAuth {
			if current := strings.TrimSpace(readCurrentModel(codexHome)); current != "" && !isRetiredCodexChatGPTModel(current) {
				return current, true, "no model configured; using the Codex CLI model"
			}
			return DefaultCodexModel, true, "no model configured; using the current Codex ChatGPT default"
		}
		return "gpt-4o", true, "no model configured; using gpt-4o for API-key auth"
	}
	if mode != AuthModeCodexOAuth {
		return model, false, ""
	}
	if !isRetiredCodexChatGPTModel(model) {
		return model, false, ""
	}
	replacement := strings.TrimSpace(fallback)
	if replacement == "" || isRetiredCodexChatGPTModel(replacement) {
		if current := strings.TrimSpace(readCurrentModel(codexHome)); current != "" && !isRetiredCodexChatGPTModel(current) {
			replacement = current
		} else {
			replacement = DefaultCodexModel
		}
	}
	if strings.EqualFold(model, replacement) {
		return model, false, ""
	}
	return replacement, true, fmt.Sprintf("%s is not supported for Codex ChatGPT sign-in", model)
}

// SelectProvider builds the generative provider and records the choice.
func SelectProvider(in SelectionInput) (Provider, Selection, error) {
	pref := strings.ToLower(strings.TrimSpace(in.Preference))
	if pref == "" {
		pref = ProviderAuto
	}
	codexOK := in.CodexAvailable
	hasKey := strings.TrimSpace(in.APIKey) != ""

	switch pref {
	case ProviderCodex:
		if !codexOK {
			return nil, Selection{}, fmt.Errorf("MIRAGE_LLM_PROVIDER=codex but no Codex login is available; run 'codex login'")
		}
		model, remapped, reason := ResolveModelForAuth(AuthModeCodexOAuth, in.Model, in.FallbackModel, in.CodexHome)
		sel := Selection{
			Preference:  pref,
			AuthMode:    AuthModeCodexOAuth,
			Model:       model,
			Requested:   strings.TrimSpace(in.Model),
			Remapped:    remapped,
			RemapReason: reason,
			Source:      "codex_oauth",
		}
		return NewOpenAIProviderWithCodex(NewCodexTokenProvider(in.CodexHome), model, in.Temperature), sel, nil
	case ProviderAPIKey:
		if !hasKey {
			return nil, Selection{}, fmt.Errorf("MIRAGE_LLM_PROVIDER=api_key but OPENAI_API_KEY is empty")
		}
		model, remapped, reason := ResolveModelForAuth(AuthModeAPIKey, in.Model, in.FallbackModel, in.CodexHome)
		sel := Selection{
			Preference:  pref,
			AuthMode:    AuthModeAPIKey,
			Model:       model,
			Requested:   strings.TrimSpace(in.Model),
			Remapped:    remapped,
			RemapReason: reason,
			Source:      "api_key",
		}
		return NewOpenAIProvider(in.APIKey, model, in.Temperature), sel, nil
	case ProviderAuto:
		if codexOK {
			model, remapped, reason := ResolveModelForAuth(AuthModeCodexOAuth, in.Model, in.FallbackModel, in.CodexHome)
			sel := Selection{
				Preference:  pref,
				AuthMode:    AuthModeCodexOAuth,
				Model:       model,
				Requested:   strings.TrimSpace(in.Model),
				Remapped:    remapped,
				RemapReason: reason,
				Source:      "codex_oauth",
			}
			return NewOpenAIProviderWithCodex(NewCodexTokenProvider(in.CodexHome), model, in.Temperature), sel, nil
		}
		if hasKey {
			model, remapped, reason := ResolveModelForAuth(AuthModeAPIKey, in.Model, in.FallbackModel, in.CodexHome)
			sel := Selection{
				Preference:  pref,
				AuthMode:    AuthModeAPIKey,
				Model:       model,
				Requested:   strings.TrimSpace(in.Model),
				Remapped:    remapped,
				RemapReason: reason,
				Source:      "api_key",
			}
			return NewOpenAIProvider(in.APIKey, model, in.Temperature), sel, nil
		}
		return nil, Selection{}, fmt.Errorf("no LLM authentication available; run 'codex login' or set OPENAI_API_KEY")
	default:
		return nil, Selection{}, fmt.Errorf("unknown MIRAGE_LLM_PROVIDER %q (use auto, codex, or api_key)", pref)
	}
}

// IsPermanentModelError reports errors that will not succeed on retry with the
// same model and auth mode.
func IsPermanentModelError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	signals := []string{
		"not supported when using codex with a chatgpt account",
		"model_not_found",
		"does not exist",
		"invalid model",
		"unsupported model",
		"unknown model",
	}
	for _, signal := range signals {
		if strings.Contains(msg, signal) {
			return true
		}
	}
	return false
}
