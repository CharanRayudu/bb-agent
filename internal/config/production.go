package config

import (
	"fmt"
	"strings"
)

// IsProduction reports whether this process was started as a production deployment.
func (c *Config) IsProduction() bool {
	if c == nil {
		return false
	}
	return strings.EqualFold(c.Environment, "production")
}

// ValidateProduction rejects insecure legacy configuration.
// Development and test processes are unchanged.
func (c *Config) ValidateProduction() error {
	if c == nil || !c.IsProduction() {
		return nil
	}
	var problems []string
	if !c.AuthRequired {
		problems = append(problems, "AUTH_REQUIRED must be true")
	}
	if !acceptableSecret(c.JWTSecret) {
		problems = append(problems, "JWT_SECRET must be a non-default value of at least 32 characters")
	}
	if defaultDatabase(c.DatabaseURL) {
		problems = append(problems, "DATABASE_URL must not use the default mirage:mirage credentials")
	}
	if !c.ExecutionV2 {
		problems = append(problems, "MIRAGE_EXECUTION_V2 must be true; legacy execution is not permitted in production")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("production configuration rejected: %s", strings.Join(problems, "; "))
}

func acceptableSecret(secret string) bool {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < 32 {
		return false
	}
	switch strings.ToLower(trimmed) {
	case "secret", "changeme", "change-me", "password", "mirage", "dev", "development":
		return false
	default:
		return true
	}
}

func defaultDatabase(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "mirage:mirage@") || strings.TrimSpace(raw) == ""
}
