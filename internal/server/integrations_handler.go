package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/compliance"
	"github.com/bb-agent/mirage/internal/integrations/ticketing"
)

// registerIntegrationRoutes adds enterprise integration API endpoints.
func (s *Server) registerIntegrationRoutes() {
	// Ticketing integrations
	s.mux.HandleFunc("/api/integrations/ticket", s.authGate(RoleOperator, s.handleCreateTicket))
	s.mux.HandleFunc("/api/integrations/ticket/test", s.authGate(RoleOperator, s.handleTestTicketIntegration))

	// Compliance posture
	s.mux.HandleFunc("/api/compliance/posture", s.handleCompliancePosture)
	s.mux.HandleFunc("/api/compliance/mapping", s.handleComplianceMapping)

	// SSO / OIDC
	s.mux.HandleFunc("/api/auth/oidc/begin", s.handleOIDCBegin)
	s.mux.HandleFunc("/api/auth/oidc/callback", s.handleOIDCCallback)
}

// handleCreateTicket creates a ticket in the configured tracker from a finding.
// POST /api/integrations/ticket
func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string            `json:"provider"` // "jira" | "github" | "linear"
		Finding  ticketing.Finding `json:"finding"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Provider == "" || req.Finding.Type == "" {
		http.Error(w, "provider and finding.type are required", http.StatusBadRequest)
		return
	}

	s.configStoreMu.RLock()
	cfg := s.configStore
	s.configStoreMu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var result ticketing.TicketResult

	switch strings.ToLower(req.Provider) {
	case "jira":
		jiraCfg := ticketing.JiraConfig{
			BaseURL:   stringFromConfig(cfg, "jira_base_url"),
			Email:     stringFromConfig(cfg, "jira_email"),
			APIToken:  stringFromConfig(cfg, "jira_api_token"),
			Project:   stringFromConfig(cfg, "jira_project"),
			IssueType: stringFromConfig(cfg, "jira_issue_type"),
		}
		result = ticketing.CreateJiraTicket(ctx, jiraCfg, &req.Finding)

	case "github":
		ghCfg := ticketing.GitHubConfig{
			Token: stringFromConfig(cfg, "github_token"),
			Owner: stringFromConfig(cfg, "github_owner"),
			Repo:  stringFromConfig(cfg, "github_repo"),
		}
		result = ticketing.CreateGitHubIssue(ctx, ghCfg, &req.Finding)

	case "linear":
		linearCfg := ticketing.LinearConfig{
			APIKey:    stringFromConfig(cfg, "linear_api_key"),
			TeamID:    stringFromConfig(cfg, "linear_team_id"),
			ProjectID: stringFromConfig(cfg, "linear_project_id"),
		}
		result = ticketing.CreateLinearIssue(ctx, linearCfg, &req.Finding)

	default:
		http.Error(w, "unsupported provider: use jira, github, or linear", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if result.Error != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  result.Error.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"provider":   result.Provider,
		"ticket_id":  result.TicketID,
		"ticket_url": result.TicketURL,
	})
}

// handleTestTicketIntegration validates ticketing config without creating a real ticket.
// POST /api/integrations/ticket/test
func (s *Server) handleTestTicketIntegration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.configStoreMu.RLock()
	cfg := s.configStore
	s.configStoreMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	switch strings.ToLower(req.Provider) {
	case "jira":
		missing := missingKeys(cfg, "jira_base_url", "jira_email", "jira_api_token", "jira_project")
		if len(missing) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "missing": missing})
			return
		}
	case "github":
		missing := missingKeys(cfg, "github_token", "github_owner", "github_repo")
		if len(missing) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "missing": missing})
			return
		}
	case "linear":
		missing := missingKeys(cfg, "linear_api_key", "linear_team_id")
		if len(missing) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "missing": missing})
			return
		}
	default:
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "provider": req.Provider})
}

// handleCompliancePosture returns a compliance posture report for all findings.
// GET /api/compliance/posture
func (s *Server) handleCompliancePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Collect distinct finding types from metadata
	typeSet := map[string]bool{}
	for _, f := range findings {
		if ft, ok := f.Metadata["finding_type"].(string); ok && ft != "" {
			typeSet[ft] = true
		} else if f.Title != "" {
			typeSet[f.Title] = true
		}
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}

	posture := compliance.GeneratePosture(types)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"frameworks":     compliance.SupportedFrameworks(),
		"posture":        posture,
		"finding_types":  types,
		"total_findings": len(findings),
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleComplianceMapping returns the control mapping for a specific finding type.
// GET /api/compliance/mapping?type=XSS
func (s *Server) handleComplianceMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findingType := r.URL.Query().Get("type")
	if findingType == "" {
		http.Error(w, "type query parameter required", http.StatusBadRequest)
		return
	}

	mapping := compliance.MapFinding(findingType)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mapping)
}

// handleOIDCBegin initiates an OIDC/OAuth2 login flow.
// GET /api/auth/oidc/begin?provider=google|github|okta&redirect_uri=...
func (s *Server) handleOIDCBegin(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/"
	}

	s.configStoreMu.RLock()
	cfg := s.configStore
	s.configStoreMu.RUnlock()

	var authURL string
	switch strings.ToLower(provider) {
	case "google":
		clientID := stringFromConfig(cfg, "oidc_google_client_id")
		if clientID == "" {
			http.Error(w, "Google OIDC not configured (oidc_google_client_id missing)", http.StatusBadRequest)
			return
		}
		authURL = "https://accounts.google.com/o/oauth2/v2/auth" +
			"?response_type=code" +
			"&client_id=" + clientID +
			"&redirect_uri=" + redirectURI +
			"&scope=openid+email+profile" +
			"&state=mirage-oidc"

	case "github":
		clientID := stringFromConfig(cfg, "oidc_github_client_id")
		if clientID == "" {
			http.Error(w, "GitHub OAuth not configured (oidc_github_client_id missing)", http.StatusBadRequest)
			return
		}
		authURL = "https://github.com/login/oauth/authorize" +
			"?client_id=" + clientID +
			"&scope=user:email" +
			"&state=mirage-oidc"

	case "okta":
		domain := stringFromConfig(cfg, "oidc_okta_domain")
		clientID := stringFromConfig(cfg, "oidc_okta_client_id")
		if domain == "" || clientID == "" {
			http.Error(w, "Okta OIDC not configured (oidc_okta_domain, oidc_okta_client_id required)", http.StatusBadRequest)
			return
		}
		authURL = "https://" + domain + "/oauth2/v1/authorize" +
			"?response_type=code" +
			"&client_id=" + clientID +
			"&redirect_uri=" + redirectURI +
			"&scope=openid+email+profile" +
			"&state=mirage-oidc"

	default:
		http.Error(w, "unsupported provider: use google, github, or okta", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles the OAuth2 callback — exchanges code for token.
// GET /api/auth/oidc/callback?code=...&state=...
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	// In production this would exchange the code for a token and create a session.
	// For now, return the code so the frontend can complete the flow.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"code":    code,
		"message": "OIDC callback received — exchange code for token using your OAuth2 client",
	})
}

// helpers

func stringFromConfig(cfg map[string]interface{}, key string) string {
	v, _ := cfg[key].(string)
	return v
}

func missingKeys(cfg map[string]interface{}, keys ...string) []string {
	var missing []string
	for _, k := range keys {
		if stringFromConfig(cfg, k) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}
