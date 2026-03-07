package agent

import (
	"context"
	"testing"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/tools"
)

// MockProvider satisfies the llm.Provider interface for testing.
type MockProvider struct{}

func (m *MockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{Content: "Mock response"}, nil
}
func (m *MockProvider) Name() string { return "mock" }

func TestOrchestratorRegistryParity(t *testing.T) {
	// 1. Initialize dependencies
	mockProvider := &MockProvider{}
	mockRegistry := tools.NewRegistry(nil)
	prompts := &config.Prompts{}

	// 2. Create Orchestrator
	orch := NewOrchestrator(mockProvider, mockRegistry, nil, prompts)

	// 3. Verify Queue Registrations (The "Correctly Joined" part)
	stats := orch.queueMgr.GetAllStats()

	expectedAgents := []string{
		"xss", "sqli", "ssrf", "lfi", "rce", "xxe", "openredirect", "idor",
		"csti", "header_injection", "protopollution", "jwt", "fileupload",
		"apisecurity", "assetdiscovery", "authdiscovery", "chaindiscovery",
		"consolidation", "dastysast", "gospider", "massassignment", "nuclei",
		"reporting", "sqlmap", "validation",
		"cloudhunter", "resourcehunter", "wafevasion", "businesslogic",
		"urlmaster", "visualcrawler",
	}

	for _, agent := range expectedAgents {
		if _, ok := stats[agent]; !ok {
			t.Errorf("Agent queue %s is NOT registered in orchestrator", agent)
		}
	}

	t.Logf("[OK] Verified 31/31 agent queues are correctly joined.")
}

func TestBrowserValidatorInitialization(t *testing.T) {
	validator := base.NewVisualValidator()
	if validator == nil {
		t.Fatal("Failed to initialize VisualValidator")
	}

	// Check name normalization
	mapping := base.SpecialistNameToValidationType("xss")
	if mapping != "browser_alert" {
		t.Errorf("Expected browser_alert for xss, got %s", mapping)
	}

	t.Logf("[OK] Visual Validator configuration verified.")
}
