package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/remediation"
)

func (s *Server) registerRemediationTrackingRoutes() {
	s.mux.HandleFunc("/api/remediation/items", s.authGateMethods(RoleOperator, s.handleRemediationItems, http.MethodPost))
	s.mux.HandleFunc("/api/remediation/items/", s.authGateMethods(RoleOperator, s.handleRemediationItem, http.MethodPost, http.MethodDelete))
	s.mux.HandleFunc("/api/remediation/metrics", s.handleRemediationMetrics)
	s.mux.HandleFunc("/api/remediation/promote", s.authGate(RoleOperator, s.handlePromoteFindings))
}

// handleRemediationItems — GET list, POST create from finding
func (s *Server) handleRemediationItems(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		filter := r.URL.Query().Get("status")
		items := s.remStore.List(filter)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": items,
			"count": len(items),
		})

	case http.MethodPost:
		var req struct {
			FindingID   string  `json:"finding_id"`
			Title       string  `json:"title"`
			Description string  `json:"description"`
			Severity    string  `json:"severity"`
			Target      string  `json:"target"`
			FindingType string  `json:"finding_type"`
			FlowID      string  `json:"flow_id"`
			RiskScore   float64 `json:"risk_score"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Title == "" {
			http.Error(w, "title is required", http.StatusBadRequest)
			return
		}
		it := s.remStore.Create(req.FindingID, req.Title, req.Description,
			req.Severity, req.Target, req.FindingType, req.FlowID, req.RiskScore)
		json.NewEncoder(w).Encode(it)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRemediationItem handles /api/remediation/items/:id[/notes|/status|/ticket]
func (s *Server) handleRemediationItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/remediation/items/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "item ID required", http.StatusBadRequest)
		return
	}
	id := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	switch sub {
	case "notes":
		s.handleItemNotes(w, r, id)
	case "status":
		s.handleItemStatus(w, r, id)
	case "ticket":
		s.handleItemTicket(w, r, id)
	default:
		s.handleItemCRUD(w, r, id)
	}
}

func (s *Server) handleItemCRUD(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		it, ok := s.remStore.Get(id)
		if !ok {
			http.Error(w, "item not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(it)

	case http.MethodDelete:
		if err := s.remStore.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/remediation/items/:id/status  { status, assignee }
func (s *Server) handleItemStatus(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Status   remediation.Status `json:"status"`
		Assignee string             `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := s.remStore.UpdateStatus(id, req.Status, req.Assignee); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	it, _ := s.remStore.Get(id)
	json.NewEncoder(w).Encode(it)
}

// POST /api/remediation/items/:id/notes  { author, content }
func (s *Server) handleItemNotes(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Author  string `json:"author"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		http.Error(w, "content is required", http.StatusBadRequest)
		return
	}
	if req.Author == "" {
		req.Author = "analyst"
	}
	note, err := s.remStore.AddNote(id, req.Author, req.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(note)
}

// POST /api/remediation/items/:id/ticket  { provider: "jira"|"github", config: {...} }
func (s *Server) handleItemTicket(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	it, ok := s.remStore.Get(id)
	if !ok {
		http.Error(w, "item not found", http.StatusNotFound)
		return
	}

	var req struct {
		Provider string                 `json:"provider"` // jira | github
		Config   map[string]interface{} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	str := func(k string) string {
		v, _ := req.Config[k].(string)
		return v
	}
	intVal := func(k string) int {
		if v, ok := req.Config[k].(float64); ok {
			return int(v)
		}
		return 0
	}

	switch req.Provider {
	case "jira":
		cfg := remediation.JiraConfig{
			BaseURL:  str("base_url"),
			Email:    str("email"),
			APIToken: str("api_token"),
			Project:  str("project"),
		}
		ticket, err := remediation.CreateJiraIssue(r.Context(), cfg, it)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		_ = s.remStore.SetTicket(id, ticket.Key, ticket.URL, 0, "")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "jira_key": ticket.Key, "url": ticket.URL})

	case "github":
		cfg := remediation.GitHubConfig{
			Token: str("token"),
			Owner: str("owner"),
			Repo:  str("repo"),
		}
		issue, err := remediation.CreateGitHubIssue(r.Context(), cfg, it)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		_ = intVal("_") // suppress lint
		_ = s.remStore.SetTicket(id, "", "", issue.Number, issue.URL)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "issue": issue.Number, "url": issue.URL})

	default:
		http.Error(w, "unsupported provider (jira|github)", http.StatusBadRequest)
	}
}

// GET /api/remediation/metrics
func (s *Server) handleRemediationMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	items := s.remStore.List("")
	m := remediation.ComputeMetrics(items)
	json.NewEncoder(w).Encode(m)
}

// POST /api/remediation/promote  — bulk-promotes findings to remediation items
// Body: { finding_ids: ["id1", "id2"] } or {} for all critical/high untracked
func (s *Server) handlePromoteFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		FindingIDs  []string `json:"finding_ids"`
		AutoPromote bool     `json:"auto_promote"` // promote all critical+high
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wantIDs := map[string]bool{}
	for _, id := range req.FindingIDs {
		wantIDs[id] = true
	}

	created := 0
	skipped := 0
	for _, f := range findings {
		fid := f.ID
		if !req.AutoPromote && !wantIDs[fid] {
			continue
		}
		if req.AutoPromote && f.Severity != "critical" && f.Severity != "high" {
			continue
		}
		// Skip if already tracked
		if existing := s.remStore.ByFindingID(fid); existing != nil {
			skipped++
			continue
		}
		ft := globalFindingType(f)
		s.remStore.Create(fid, f.Title, f.Content, f.Severity, f.Target, ft, f.FlowID.String(), 0)
		created++
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"created": created,
		"skipped": skipped,
	})
}
