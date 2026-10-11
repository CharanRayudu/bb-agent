package config

import "testing"

func TestProductionRejectsLegacyDefaults(t *testing.T) {
	cfg := &Config{
		Environment: "production",
		DatabaseURL: "postgres://mirage:mirage@localhost:5432/miragedb",
	}
	if err := cfg.ValidateProduction(); err == nil {
		t.Fatal("expected production defaults to be rejected")
	}
}

func TestProductionAcceptsExplicitSecureConfig(t *testing.T) {
	cfg := &Config{
		Environment:  "production",
		AuthRequired: true,
		JWTSecret:    "0123456789abcdef0123456789abcdef",
		DatabaseURL:  "postgres://app:not-the-default@db:5432/mirage",
		ExecutionV2:  true,
	}
	if err := cfg.ValidateProduction(); err != nil {
		t.Fatal(err)
	}
}

func TestDevelopmentSkipsProductionChecks(t *testing.T) {
	cfg := &Config{Environment: "development", DatabaseURL: "postgres://mirage:mirage@localhost/miragedb"}
	if err := cfg.ValidateProduction(); err != nil {
		t.Fatal(err)
	}
}
