package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server
	ServerPort int
	ServerHost string

	// Database
	DatabaseURL string

	// Docker
	DockerHost          string
	SandboxImage        string
	FirewallHelperImage string

	// LLM -- Codex OAuth (preferred) or API key (fallback)
	CodexHome         string // Path to Codex CLI config dir (default: ~/.codex)
	OpenAIAPIKey      string // Optional fallback: raw API key
	OpenAIModel       string
	OpenAITemperature float64
	LLMProvider       string // auto, codex, or api_key
	LLMFallbackModel  string // remap target when Codex ChatGPT rejects the configured model

	// Microsoft Foundry Decision-1. Empty endpoint leaves specialist
	// selection on the existing deterministic rules.
	FoundryEndpoint      string
	FoundryDeployment    string
	FoundryAPIKey        string
	FoundryTimeout       time.Duration
	FoundryMinConfidence float64

	// Auth
	JWTSecret     string
	AuthRequired  bool   // if true, endpoints without a valid token are rejected (401). Default false.
	WebhookSecret string // HMAC-SHA256 secret for /api/cicd/trigger. Empty disables verification.

	// CORS
	// AllowedOrigins is an explicit allow-list of origins for browser CORS.
	// If empty, CORS responds with the first value from Origin only for same-host requests.
	AllowedOrigins []string

	// Search
	TavilyAPIKey string
	ShodanAPIKey string

	// Mirage v2 migration flags. Default off so existing deployments keep
	// their current behavior. Production startup rejects that legacy path.
	Environment      string
	ExecutionV2      bool
	DurableWorkflows bool
	VerificationV2   bool
	SkillsV2         bool
}

func Load() (*Config, error) {
	port, _ := strconv.Atoi(getEnv("SERVER_PORT", "8443"))
	temp, _ := strconv.ParseFloat(getEnv("OPENAI_TEMPERATURE", "0.1"), 64)

	cfg := &Config{
		ServerPort:           port,
		ServerHost:           getEnv("SERVER_HOST", "0.0.0.0"),
		DatabaseURL:          getEnv("DATABASE_URL", "postgres://mirage:mirage@localhost:5432/miragedb?sslmode=disable"),
		DockerHost:           getEnv("DOCKER_HOST", ""),
		SandboxImage:         getEnv("SANDBOX_IMAGE", "mirage-tools:latest"),
		FirewallHelperImage:  getEnv("FIREWALL_HELPER_IMAGE", "mirage-firewall:local"),
		CodexHome:            getEnv("CODEX_HOME", ""),
		OpenAIAPIKey:         getEnv("OPENAI_API_KEY", ""),
		OpenAIModel:          getEnv("OPENAI_MODEL", "gpt-6.1-sol"),
		OpenAITemperature:    temp,
		LLMProvider:          strings.ToLower(getEnv("MIRAGE_LLM_PROVIDER", "auto")),
		LLMFallbackModel:     getEnv("MIRAGE_LLM_FALLBACK_MODEL", ""),
		FoundryEndpoint:      getEnv("FOUNDRY_ENDPOINT", ""),
		FoundryDeployment:    getEnv("FOUNDRY_DEPLOYMENT", ""),
		FoundryAPIKey:        getEnv("FOUNDRY_API_KEY", ""),
		FoundryTimeout:       time.Duration(envInt("FOUNDRY_TIMEOUT_SECONDS", 15)) * time.Second,
		FoundryMinConfidence: envFloat("FOUNDRY_MIN_CONFIDENCE", 0.55),
		JWTSecret:            getEnv("JWT_SECRET", ""),
		AuthRequired:         strings.EqualFold(getEnv("AUTH_REQUIRED", "false"), "true"),
		WebhookSecret:        getEnv("WEBHOOK_SECRET", ""),
		AllowedOrigins:       splitList(getEnv("ALLOWED_ORIGINS", "")),
		TavilyAPIKey:         getEnv("TAVILY_API_KEY", ""),
		ShodanAPIKey:         getEnv("SHODAN_API_KEY", ""),
		Environment:          getEnv("MIRAGE_ENV", "development"),
		ExecutionV2:          envBool("MIRAGE_EXECUTION_V2"),
		DurableWorkflows:     envBool("MIRAGE_DURABLE_WORKFLOWS"),
		VerificationV2:       envBool("MIRAGE_VERIFICATION_V2"),
		SkillsV2:             envBool("MIRAGE_SKILLS_V2"),
	}

	return cfg, nil
}

// ExecutionModeStatus names the scanner path selected by MIRAGE_EXECUTION_V2.
func (c *Config) ExecutionModeStatus() string {
	if c != nil && c.ExecutionV2 {
		return "execution mode v2: per-flow sandbox and action gateway"
	}
	return "execution mode legacy: shared sandbox; set MIRAGE_EXECUTION_V2=true for v2"
}

// DecisionRoutingStatus reports whether specialist routing will call Foundry.
// It never includes the API key.
func (c *Config) DecisionRoutingStatus() string {
	if c == nil {
		return "Decision-1 routing disabled"
	}
	switch {
	case strings.TrimSpace(c.FoundryEndpoint) == "" && strings.TrimSpace(c.FoundryDeployment) == "" && strings.TrimSpace(c.FoundryAPIKey) == "":
		return "Decision-1 routing disabled; specialist selection uses deterministic rules"
	case strings.TrimSpace(c.FoundryEndpoint) == "" || strings.TrimSpace(c.FoundryDeployment) == "" || strings.TrimSpace(c.FoundryAPIKey) == "":
		return "Decision-1 routing disabled; set FOUNDRY_ENDPOINT, FOUNDRY_DEPLOYMENT, and FOUNDRY_API_KEY together"
	default:
		return fmt.Sprintf("Decision-1 routing enabled for deployment %s (min confidence %.2f)", c.FoundryDeployment, c.FoundryMinConfidence)
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envFloat(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
