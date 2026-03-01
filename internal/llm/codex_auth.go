package llm

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// CodexAuthFile represents the structure of ~/.codex/auth.json
// Created by `codex login` when authenticating via ChatGPT OAuth
type CodexAuthFile struct {
	AuthMode     string       `json:"auth_mode"`
	OpenAIAPIKey *string      `json:"OPENAI_API_KEY"`
	Tokens       *CodexTokens `json:"tokens"`
	AccountID    string       `json:"account_id"`
	LastRefresh  string       `json:"last_refresh"`
	// Legacy flat format
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
}

// CodexTokens holds the nested token structure used by codex-cli v0.104+
type CodexTokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
}

// CodexTokenProvider reads and caches OAuth tokens from the Codex CLI auth file
type CodexTokenProvider struct {
	codexHome   string
	cachedToken string
	mu          sync.RWMutex
}

// NewCodexTokenProvider creates a provider that reads tokens from the codex auth file
func NewCodexTokenProvider(codexHome string) *CodexTokenProvider {
	if codexHome == "" {
		codexHome = defaultCodexHome()
	}
	return &CodexTokenProvider{codexHome: codexHome}
}

// GetToken returns the current OAuth access token, reading from auth.json
func (c *CodexTokenProvider) GetToken() (string, error) {
	c.mu.RLock()
	if c.cachedToken != "" {
		token := c.cachedToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	return c.RefreshToken()
}

// RefreshToken re-reads the auth.json file to get a fresh token
func (c *CodexTokenProvider) RefreshToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	authPath := filepath.Join(c.codexHome, "auth.json")

	data, err := os.ReadFile(authPath)
	if err != nil {
		return "", fmt.Errorf(
			"failed to read Codex auth file at %s: %w\n"+
				"Run 'codex login' first to authenticate with ChatGPT",
			authPath, err,
		)
	}

	var auth CodexAuthFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return "", fmt.Errorf("failed to parse Codex auth file: %w", err)
	}

	// Extract the access token — try multiple known formats
	var token string

	// Format 1 (v0.104+): nested tokens object with id_token or access_token
	if auth.Tokens != nil {
		if auth.Tokens.AccessToken != "" {
			token = auth.Tokens.AccessToken
		} else if auth.Tokens.IDToken != "" {
			// Codex CLI stores the OAuth credential as id_token
			token = auth.Tokens.IDToken
		}
	}

	// Format 2 (legacy): flat access_token field
	if token == "" && auth.AccessToken != "" {
		token = auth.AccessToken
	}

	if token == "" {
		return "", fmt.Errorf(
			"no access token found in %s\n"+
				"Run 'codex login' to re-authenticate with ChatGPT",
			authPath,
		)
	}

	// Check expiry / freshness
	if auth.LastRefresh != "" {
		if t, err := time.Parse(time.RFC3339Nano, auth.LastRefresh); err == nil {
			age := time.Since(t)
			if age > 24*time.Hour {
				log.Printf("⚠️  Codex token last refreshed %s ago — may need 'codex login' to refresh", age.Round(time.Hour))
			}
		}
	}

	c.cachedToken = token
	log.Printf("✅ Loaded Codex OAuth token from %s (auth_mode: %s)", authPath, auth.AuthMode)
	return token, nil
}

// ClearCache invalidates the cached token, forcing a re-read on next call
func (c *CodexTokenProvider) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cachedToken = ""
}

// IsAvailable checks if the codex auth file exists
func (c *CodexTokenProvider) IsAvailable() bool {
	authPath := filepath.Join(c.codexHome, "auth.json")
	_, err := os.Stat(authPath)
	return err == nil
}

// defaultCodexHome returns the default Codex config directory
func defaultCodexHome() string {
	// Check CODEX_HOME env first
	if home := os.Getenv("CODEX_HOME"); home != "" {
		return home
	}

	// Default: ~/.codex (or %USERPROFILE%\.codex on Windows)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		if runtime.GOOS == "windows" {
			return filepath.Join(os.Getenv("USERPROFILE"), ".codex")
		}
		return filepath.Join("/root", ".codex")
	}
	return filepath.Join(homeDir, ".codex")
}
