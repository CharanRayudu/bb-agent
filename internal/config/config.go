package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// Server
	ServerPort int
	ServerHost string

	// Database
	DatabaseURL string

	// Docker
	DockerHost   string
	SandboxImage string

	// LLM -- Codex OAuth (preferred) or API key (fallback)
	CodexHome         string // Path to Codex CLI config dir (default: ~/.codex)
	OpenAIAPIKey      string // Optional fallback: raw API key
	OpenAIModel       string
	OpenAITemperature float64
	LLMProxyURL       string // If set, forward Codex requests through this proxy (e.g. http://localhost:8765)

	// Auth
	JWTSecret     string
	AuthRequired  bool // if true, endpoints without a valid token are rejected (401). Default false.
	WebhookSecret string // HMAC-SHA256 secret for /api/cicd/trigger. Empty disables verification.

	// CORS
	// AllowedOrigins is an explicit allow-list of origins for browser CORS.
	// If empty, CORS responds with the first value from Origin only for same-host requests.
	AllowedOrigins []string

	// Search
	TavilyAPIKey string
	ShodanAPIKey string
}

func Load() (*Config, error) {
	port, _ := strconv.Atoi(getEnv("SERVER_PORT", "8443"))
	temp, _ := strconv.ParseFloat(getEnv("OPENAI_TEMPERATURE", "0.1"), 64)

	cfg := &Config{
		ServerPort:        port,
		ServerHost:        getEnv("SERVER_HOST", "0.0.0.0"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://mirage:mirage@localhost:5432/miragedb?sslmode=disable"),
		DockerHost:        getEnv("DOCKER_HOST", ""),
		SandboxImage:      getEnv("SANDBOX_IMAGE", "mirage-tools:latest"),
		CodexHome:         getEnv("CODEX_HOME", ""),
		OpenAIAPIKey:      getEnv("OPENAI_API_KEY", ""),
		OpenAIModel:       getEnv("OPENAI_MODEL", "gpt-4o"),
		OpenAITemperature: temp,
		LLMProxyURL:       getEnv("LLM_PROXY_URL", ""),
		JWTSecret:         getEnv("JWT_SECRET", ""),
		AuthRequired:      strings.EqualFold(getEnv("AUTH_REQUIRED", "false"), "true"),
		WebhookSecret:     getEnv("WEBHOOK_SECRET", ""),
		AllowedOrigins:    splitList(getEnv("ALLOWED_ORIGINS", "")),
		TavilyAPIKey:      getEnv("TAVILY_API_KEY", ""),
		ShodanAPIKey:      getEnv("SHODAN_API_KEY", ""),
	}

	// No hard requirement on API key anymore -- Codex OAuth is checked at runtime
	if cfg.OpenAIAPIKey != "" {
		log.Println("[KEY] Using OpenAI API key for authentication")
	} else {
		log.Println("[AUTH] No API key set -- will use Codex CLI OAuth (run 'codex login' first)")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
