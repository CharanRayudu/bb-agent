package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/agent"
	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/docker"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// OperatorAnnotation is a note left by an operator on a flow during live collaboration.
type OperatorAnnotation struct {
	ID        string    `json:"id"`
	FlowID    string    `json:"flow_id"`
	Operator  string    `json:"operator"` // username or "anonymous"
	Note      string    `json:"note"`
	FindingID string    `json:"finding_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Server is the main HTTP server
type Server struct {
	cfg      *config.Config
	db       *sql.DB
	queries  *database.Queries
	mux      *http.ServeMux
	upgrader websocket.Upgrader

	// WebSocket clients
	clients     map[*websocket.Conn]bool
	clientsMu   sync.RWMutex
	broadcastMu sync.Mutex

	// Agent
	orchestrator *agent.Orchestrator

	// Active scan cancellation tracking
	activeScans   map[uuid.UUID]context.CancelFunc
	activeScansMu sync.RWMutex

	// Live operator collaboration
	operatorAnnotations   map[string][]OperatorAnnotation
	operatorAnnotationsMu sync.RWMutex

	// Operational subsystems
	rbac               *agent.RBAC
	auditLog           *agent.AuditLog
	scheduler          *agent.Scheduler
	remediationTracker *agent.RemediationTracker
	surfaceStore       *agent.SurfaceStore

	// CI/CD webhook HMAC secret (optional)
	webhookSecret string

	// Authenticated session management
	authSessions map[string]*base.AuthSession
	authMu       sync.RWMutex

	// llmProvider is used for stateless LLM API requests (e.g. /api/mutate).
	// May be nil when no auth is configured.
	llmProvider llm.Provider
}

// New creates a new server instance
func New(cfg *config.Config, db *sql.DB) *Server {
	rbac := agent.NewRBAC()
	auditLog := agent.NewAuditLog()
	surfaceStore := agent.NewSurfaceStore()
	remediationTracker := agent.NewRemediationTracker()

	// Scheduler trigger will create a new flow when fired.
	// We use a placeholder here; the real trigger is set after s is constructed.
	var s *Server
	scheduler := agent.NewScheduler(func(target, profile string) {
		if s != nil {
			s.schedulerTrigger(target, profile)
		}
	})

	// Build a shared LLM provider for stateless requests (e.g. /api/mutate).
	// Mirrors the logic in runAgent: prefer Codex OAuth, fall back to API key.
	var sharedProvider llm.Provider
	codexAuth := llm.NewCodexTokenProvider(cfg.CodexHome)
	if codexAuth.IsAvailable() {
		sharedProvider = llm.NewOpenAIProviderWithCodex(codexAuth, cfg.OpenAIModel, cfg.OpenAITemperature)
	} else if cfg.OpenAIAPIKey != "" {
		sharedProvider = llm.NewOpenAIProvider(cfg.OpenAIAPIKey, cfg.OpenAIModel, cfg.OpenAITemperature)
	}
	if sharedProvider != nil {
		sharedProvider = llm.NewResilientProvider(sharedProvider)
	}

	s = &Server{
		cfg:     cfg,
		db:      db,
		queries: database.NewQueries(db),
		mux:     http.NewServeMux(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients:             make(map[*websocket.Conn]bool),
		activeScans:         make(map[uuid.UUID]context.CancelFunc),
		operatorAnnotations: make(map[string][]OperatorAnnotation),
		authSessions:        make(map[string]*base.AuthSession),
		rbac:               rbac,
		auditLog:           auditLog,
		scheduler:          scheduler,
		remediationTracker: remediationTracker,
		surfaceStore:       surfaceStore,
		llmProvider:        sharedProvider,
	}

	s.setupRoutes()
	return s
}

// schedulerTrigger is the callback invoked by the Scheduler to start a new scan.
func (s *Server) schedulerTrigger(target, profile string) {
	flow, err := s.queries.CreateFlow("Scheduled: "+target, "Scheduled scan via profile "+profile, target)
	if err != nil {
		log.Printf("[SCHEDULER] Failed to create flow for %s: %v", target, err)
		return
	}
	s.auditLog.Record("scheduler", "scan_started", flow.ID.String(), map[string]interface{}{
		"target":  target,
		"profile": profile,
	}, "")
	go s.runAgent(flow.ID, "Automated scheduled scan", "", 0, 0)
}

func (s *Server) setupRoutes() {
	// API routes -- register more specific patterns first so /api/flows/{id} and /api/flows/create
	// are handled by handleFlow/handleCreateFlow, not handleFlows (which only allows GET and would return 405 for DELETE)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/models", s.handleModels)
	s.mux.HandleFunc("/api/findings", s.handleFindings)
	s.mux.HandleFunc("/api/findings/remediation", s.handleRemediationList)
	s.mux.HandleFunc("/api/findings/", s.handleFindingSubroute)
	s.mux.HandleFunc("/api/flows/create", s.handleCreateFlow)
	s.mux.HandleFunc("/api/flows/", s.handleFlow)
	s.mux.HandleFunc("/api/flows", s.handleFlows)

	// Operational routes
	s.mux.HandleFunc("/api/schedules", s.handleSchedules)
	s.mux.HandleFunc("/api/schedules/", s.handleScheduleByID)
	s.mux.HandleFunc("/api/users", s.handleUsers)
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/cicd/trigger", s.handleCICDTrigger)

	// LLM mutation endpoint
	s.mux.HandleFunc("/api/mutate", s.handleMutate)

	// Extended API routes (knowledge graph, analytics, config, metrics, schedules)
	s.registerExtendedRoutes()

	// WebSocket
	s.mux.HandleFunc("/ws", s.handleWebSocket)

	// Serve screenshots
	s.mux.Handle("/screenshots/", http.StripPrefix("/screenshots/", http.FileServer(http.Dir("logs/screenshots"))))

	// Serve frontend static files
	s.mux.Handle("/", http.FileServer(http.Dir("frontend/dist")))
}

// Start runs the HTTP server
// Handler returns the server's HTTP handler (useful for testing).
func (s *Server) Handler() http.Handler {
	return corsMiddleware(s.mux)
}

func (s *Server) Start(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: corsMiddleware(s.mux),
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down HTTP server...")
		srv.Close()
	}()

	return srv.ListenAndServe()
}

// ============ Handlers ============

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "mirage",
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	models := llm.GetAvailableModels(s.cfg.CodexHome)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flows, err := s.queries.ListFlows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flows)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		log.Printf("Error fetching findings: %v", err)
		http.Error(w, "Failed to fetch findings", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	// Simple router for /api/flows/{id} vs /api/flows/{id}/events
	path := r.URL.Path[len("/api/flows/"):]

	// Check if this is a sub-route like /api/flows/{id}/events or /api/flows/{id}/cancel
	if len(path) > 36 && path[36] == '/' {
		idStr := path[:36]
		subRoute := path[36:]
		id, err := uuid.Parse(idStr)
		if err != nil {
			http.Error(w, "Invalid flow ID", http.StatusBadRequest)
			return
		}

		if subRoute == "/events" && r.Method == http.MethodGet {
			s.handleFlowEvents(w, r, id)
			return
		} else if subRoute == "/ledger" && r.Method == http.MethodGet {
			s.handleFlowLedger(w, r, id)
			return
		} else if subRoute == "/cancel" && r.Method == http.MethodPost {
			s.handleCancelFlow(w, r, id)
			return
		} else if subRoute == "/annotations" && r.Method == http.MethodGet {
			s.handleGetAnnotations(w, r, id)
			return
		} else if subRoute == "/annotate" && r.Method == http.MethodPost {
			s.handleAnnotateFlow(w, r, id)
			return
		} else if subRoute == "/pause" && r.Method == http.MethodPost {
			s.handlePauseFlow(w, r, id)
			return
		} else if subRoute == "/resume" && r.Method == http.MethodPost {
			s.handleResumeFlow(w, r, id)
			return
		} else if subRoute == "/surface-diff" && r.Method == http.MethodGet {
			s.handleSurfaceDiff(w, r, id)
			return
		} else if subRoute == "/report/html" && r.Method == http.MethodGet {
			s.handleHTMLReport(w, r, id)
			return
		} else if subRoute == "/report/burp" && r.Method == http.MethodGet {
			s.handleBurpReport(w, r, id)
			return
		} else if subRoute == "/report/nuclei" && r.Method == http.MethodGet {
			s.handleNucleiReport(w, r, id)
			return
		} else if subRoute == "/compliance" && r.Method == http.MethodGet {
			s.handleCompliance(w, r, id)
			return
		} else if subRoute == "/screenshots" && r.Method == http.MethodGet {
			s.handleGetScreenshots(w, r, id)
			return
		} else if subRoute == "/screenshots/capture" && r.Method == http.MethodPost {
			s.handleCaptureScreenshot(w, r, id)
			return
		} else if strings.HasPrefix(subRoute, "/screenshots/") && r.Method == http.MethodGet {
			sid := subRoute[len("/screenshots/"):]
			s.handleGetScreenshotImage(w, r, id, sid)
			return
		} else if subRoute == "/auth" {
			s.handleFlowAuth(w, r, id)
			return
		} else if subRoute == "/hypotheses" && r.Method == http.MethodGet {
			s.handleFlowHypotheses(w, r, id)
			return
		}

		http.Error(w, "Endpoint or method not supported", http.StatusNotFound)
		return
	}

	// Otherwise, handle regular FlowByID (GET) or DeleteFlow (DELETE)
	id, err := uuid.Parse(path)
	if err != nil {
		http.Error(w, "Invalid flow ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleFlowByID(w, r, id)
	case http.MethodDelete:
		s.handleDeleteFlow(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDeleteFlow(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("[DELETE] DELETE flow request: %s", id.String())

	flow, err := s.queries.GetFlow(id)
	if err != nil {
		log.Printf("[ERROR] Delete flow: %v", err)
		http.Error(w, "Flow not found", http.StatusNotFound)
		return
	}

	// If flow is still active, cancel it first so the orchestrator stops and we can safely delete
	if flow.Status == models.FlowStatusActive {
		s.activeScansMu.Lock()
		cancel, exists := s.activeScans[id]
		if exists {
			delete(s.activeScans, id)
		}
		s.activeScansMu.Unlock()
		if exists {
			cancel()
		}
		s.queries.UpdateFlowStatus(id, models.FlowStatusFailed)
		s.queries.UpdateTasksStatusByFlow(id, models.TaskStatusFailed, "Flow deleted by user")
		s.queries.CreateFlowEvent(id, string(agent.EventError), "Flow deleted by user.", nil)
		s.broadcast(agent.Event{
			Type:      agent.EventError,
			FlowID:    id.String(),
			Content:   "Flow deleted by user.",
			Timestamp: time.Now(),
		})
	}

	if err := s.queries.DeleteFlow(id); err != nil {
		log.Printf("[ERROR] DeleteFlow db error: %v", err)
		http.Error(w, "Failed to delete flow", http.StatusInternalServerError)
		return
	}

	log.Printf("[OK] Flow deleted: %s", id.String())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCancelFlow(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.activeScansMu.Lock()
	cancel, exists := s.activeScans[id]
	if exists {
		delete(s.activeScans, id)
	}
	s.activeScansMu.Unlock()

	if exists {
		log.Printf("[CANCEL] User requested cancellation for flow: %s", id.String())
		cancel() // This triggers <-ctx.Done() inside the orchestrator
	} else {
		log.Printf("[WARN] User requested cancellation for non-active flow: %s (force clearing status)", id.String())
	}

	// ALWAYS update database and broadcast event to ensure orphans are cleared in the UI
	s.queries.UpdateFlowStatus(id, models.FlowStatusFailed)

	// Also failure any tasks that might still be shown as pending/running
	// (This is a coarse sweep but effective for orphan cleanup)
	s.queries.UpdateTasksStatusByFlow(id, models.TaskStatusFailed, "Scan cancelled by user")

	// Persist the cancellation event so it shows up in the timeline on reload
	s.queries.CreateFlowEvent(id, string(agent.EventError), "Scan cancelled by user.", nil)

	s.broadcast(agent.Event{
		Type:      agent.EventError,
		FlowID:    id.String(),
		Content:   "Scan cancelled by user.",
		Timestamp: time.Now(),
	})

	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "scan_cancelled", id.String(), nil, r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
}

// handleFlowHypotheses returns the attack hypotheses generated for a flow,
// extracted from the event stream metadata emitted by the HypothesisEngine.
func (s *Server) handleFlowHypotheses(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	events, err := s.queries.GetFlowEvents(id)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	// Extract hypotheses from event metadata — the orchestrator emits them as
	// {"hypotheses": [...]} in the metadata field of [HYPOTHESIS] events.
	var hypotheses []interface{}
	for _, ev := range events {
		if !strings.HasPrefix(ev.Content, "[HYPOTHESIS]") {
			continue
		}
		meta, _ := ev.Metadata.(map[string]interface{})
		if meta == nil {
			continue
		}
		if hyps, ok := meta["hypotheses"]; ok {
			if list, ok := hyps.([]interface{}); ok {
				hypotheses = list
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if hypotheses == nil {
		hypotheses = []interface{}{}
	}
	json.NewEncoder(w).Encode(hypotheses)
}

func (s *Server) handleFlowByID(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flow, err := s.queries.GetFlow(id)
	if err != nil {
		http.Error(w, "Flow not found", http.StatusNotFound)
		return
	}

	// Load task ledger summary
	tasks, err := s.queries.GetTaskLedgerByFlow(id)
	if err == nil {
		flow.Tasks = tasks
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flow)
}

func (s *Server) handleFlowEvents(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Fetch from new flow_events table
	events, err := s.queries.GetFlowEvents(id)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch flow events: %v", err)
		http.Error(w, "Failed to load events", http.StatusInternalServerError)
		return
	}

	// 2. Fetch from actions table (fallback/legacy/auto-reported findings)
	actions, err := s.queries.GetActionsByFlow(id)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch actions for fallback: %v", err)
	}

	// 3. Merge and deduplicate using unique Content + Type + Timestamp (approx)
	// We use a map to deduplicate if the same event exists in both tables
	seen := make(map[string]bool)
	merged := []database.EventWithTimestamp{}

	// Add existing flow_events first
	for _, e := range events {
		key := fmt.Sprintf("%s:%s", e.Type, e.Content)
		if !seen[key] {
			merged = append(merged, e)
			seen[key] = true
		}
	}

	// Add reconstructed events from actions if not already present
	for _, a := range actions {
		sType := string(a.Type)
		var toolName string
		if sType == "command" {
			toolName = "execute_command"
		} else if sType == "analyze" || sType == "llm_call" {
			toolName = "think"
		} else if sType == "report" {
			toolName = "report_findings"
		}

		// Tool Call entry
		callContent := fmt.Sprintf("Calling tool: %s", toolName)
		callKey := "tool_call:" + callContent
		if !seen[callKey] {
			merged = append(merged, database.EventWithTimestamp{
				Type:      "tool_call",
				Content:   callContent,
				Timestamp: a.CreatedAt.Add(-time.Millisecond), // slight offset to preserve order
				Metadata: map[string]interface{}{
					"tool": toolName,
					"args": a.Input,
				},
			})
			seen[callKey] = true
		}

		// Tool Result entry
		resKey := "tool_result:" + a.Output
		if !seen[resKey] {
			merged = append(merged, database.EventWithTimestamp{
				Type:      "tool_result",
				Content:   a.Output,
				Timestamp: a.CreatedAt,
				Metadata: map[string]interface{}{
					"tool":   toolName,
					"status": a.Status,
				},
			})
			seen[resKey] = true
		}
	}

	// Re-sort results by timestamp to ensure chronological order
	// (Simple append might be out of order if actions were added between events)
	// For now, we assume ORDER BY in queries handled the bulk of it.

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(merged)
}

func (s *Server) handleFlowLedger(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ledger, err := s.queries.GetFlowLedger(id)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch flow ledger: %v", err)
		http.Error(w, "Failed to load ledger", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ledger)
}

func (s *Server) handleAnnotateFlow(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var body struct {
		Note      string `json:"note"`
		Operator  string `json:"operator"`
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Note == "" {
		http.Error(w, "note is required", http.StatusBadRequest)
		return
	}
	operator := body.Operator
	if operator == "" {
		operator = "anonymous"
	}

	annotation := OperatorAnnotation{
		ID:        uuid.New().String(),
		FlowID:    id.String(),
		Operator:  operator,
		Note:      body.Note,
		FindingID: body.FindingID,
		Timestamp: time.Now(),
	}

	s.operatorAnnotationsMu.Lock()
	s.operatorAnnotations[id.String()] = append(s.operatorAnnotations[id.String()], annotation)
	s.operatorAnnotationsMu.Unlock()

	// Broadcast to all WebSocket clients
	s.broadcast(agent.Event{
		Type:    agent.EventType("operator_annotation"),
		FlowID:  id.String(),
		Content: body.Note,
		Metadata: map[string]interface{}{
			"id":         annotation.ID,
			"operator":   annotation.Operator,
			"finding_id": annotation.FindingID,
			"timestamp":  annotation.Timestamp,
		},
		Timestamp: annotation.Timestamp,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(annotation)
}

func (s *Server) handleGetAnnotations(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	s.operatorAnnotationsMu.RLock()
	annotations := s.operatorAnnotations[id.String()]
	s.operatorAnnotationsMu.RUnlock()

	if annotations == nil {
		annotations = []OperatorAnnotation{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(annotations)
}

// CreateFlowRequest is the JSON body for creating a new flow
type CreateFlowRequest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Target            string   `json:"target"`
	Model             string   `json:"model"`
	Timeout           int      `json:"timeout"`            // Total scan timeout in minutes
	AgentTimeout      int      `json:"agent_timeout"`      // Per-agent timeout in minutes
	AdditionalTargets []string `json:"additional_targets"` // Up to 5 extra targets for multi-target scans
	Profile           string   `json:"profile"`            // Scan profile name (see agent.DefaultProfiles)
}

func (s *Server) handleCreateFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Target == "" {
		http.Error(w, "name and target are required", http.StatusBadRequest)
		return
	}

	flow, err := s.queries.CreateFlow(req.Name, req.Description, req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record audit event for scan start
	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "scan_started", flow.ID.String(), map[string]interface{}{
		"target":  req.Target,
		"name":    req.Name,
		"profile": req.Profile,
	}, r.RemoteAddr)

	// Initialize the agent and run the primary flow asynchronously
	go s.runAgent(flow.ID, req.Description, req.Model, req.Timeout, req.AgentTimeout)

	// Launch additional target flows (multi-target support, max 5)
	additionalTargets := req.AdditionalTargets
	if len(additionalTargets) > 5 {
		additionalTargets = additionalTargets[:5]
	}
	for _, additionalTarget := range additionalTargets {
		additionalTarget := additionalTarget // capture loop variable
		if additionalTarget == "" {
			continue
		}
		extraFlow, err := s.queries.CreateFlow(req.Name+" ["+additionalTarget+"]", req.Description, additionalTarget)
		if err != nil {
			log.Printf("[WARN] Failed to create additional target flow for %s: %v", additionalTarget, err)
			continue
		}
		go s.runAgent(extraFlow.ID, req.Description, req.Model, req.Timeout, req.AgentTimeout)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

func (s *Server) runAgent(flowID uuid.UUID, prompt string, selectedModel string, timeout int, agentTimeout int) {
	// Create Docker sandbox
	sandbox, err := docker.NewSandbox(s.cfg.DockerHost, s.cfg.SandboxImage)
	if err != nil {
		log.Printf("[ERROR] Failed to create sandbox: %v", err)
		s.queries.UpdateFlowStatus(flowID, models.FlowStatusFailed)
		s.broadcast(agent.Event{
			Type:    agent.EventError,
			FlowID:  flowID.String(),
			Content: fmt.Sprintf("Failed to create Docker sandbox: %v", err),
		})
		return
	}
	defer sandbox.Close()

	// Use the user-selected model, or fall back to config default
	model := selectedModel
	if model == "" {
		model = s.cfg.OpenAIModel
	}
	log.Printf("[BRAIN] Using model: %s", model)

	// Create LLM provider -- prefer Codex OAuth, fall back to API key
	var provider llm.Provider

	codexAuth := llm.NewCodexTokenProvider(s.cfg.CodexHome)
	if codexAuth.IsAvailable() {
		log.Println("[AUTH] Using Codex CLI OAuth for LLM authentication")
		provider = llm.NewOpenAIProviderWithCodex(codexAuth, model, s.cfg.OpenAITemperature)
	} else if s.cfg.OpenAIAPIKey != "" {
		log.Println("[KEY] Using OpenAI API key for LLM authentication")
		provider = llm.NewOpenAIProvider(s.cfg.OpenAIAPIKey, model, s.cfg.OpenAITemperature)
	} else {
		errMsg := "No LLM authentication available. Run 'codex login' or set OPENAI_API_KEY"
		log.Printf("[ERROR] %s", errMsg)
		s.queries.UpdateFlowStatus(flowID, models.FlowStatusFailed)
		s.broadcast(agent.Event{
			Type:    agent.EventError,
			FlowID:  flowID.String(),
			Content: errMsg,
		})
	}

	// Wrap with ResilientProvider to handle transient connection errors (Brain-Hardening)
	provider = llm.NewResilientProvider(provider)

	// Create tool registry
	registry := tools.NewRegistry(sandbox)

	// Load externalized prompts
	prompts, err := config.LoadPrompts("prompts.yaml")
	if err != nil {
		log.Printf("[WARN] Failed to load prompts.yaml: %v (using defaults)", err)
		prompts = &config.Prompts{}
	}

	// Create orchestrator
	orchestrator := agent.NewOrchestrator(provider, registry, s.db, prompts)
	orchestrator.SetEventHandler(func(event agent.Event) {
		// Mirage 2.0: Persist events so they survive page refreshes
		flowIDuuid, err := uuid.Parse(event.FlowID)
		if err != nil {
			log.Printf("[WARN] Failed to parse flow ID for event persistence: %v", err)
		} else {
			if err := s.queries.CreateFlowEvent(flowIDuuid, string(event.Type), event.Content, event.Metadata); err != nil {
				log.Printf("[ERROR] Database error saving flow event: %v", err)
			}
		}
		s.broadcast(event)
	})

	// Wrap Orchestrator with Conductor
	conductor := agent.NewConductor(orchestrator, orchestrator.GetEventBus())
	if timeout != 0 {
		conductor.SetScanTimeout(time.Duration(timeout) * time.Minute)
	}
	if agentTimeout != 0 {
		conductor.SetAgentTimeout(time.Duration(agentTimeout) * time.Minute)
	}
	orchestrator.SetConductor(conductor)

	// Subscribe to internal Conductor metrics and broadcast them
	orchestrator.GetEventBus().Subscribe("queue_metrics", func(data interface{}) {
		metrics, ok := data.(map[string]interface{})
		if !ok {
			return
		}
		s.broadcast(agent.Event{
			Type:      agent.EventMessage,
			FlowID:    flowID.String(),
			TaskID:    "conductor",
			Content:   "[STATS] Queue Metrics Update",
			Metadata:  metrics,
			Timestamp: time.Now(),
		})
	})

	// Setup cancellable context and track it
	ctx, cancel := context.WithCancel(context.Background())
	s.activeScansMu.Lock()
	s.activeScans[flowID] = cancel
	s.activeScansMu.Unlock()

	// Ensure cleanup when runAgent completes
	defer func() {
		s.activeScansMu.Lock()
		delete(s.activeScans, flowID)
		s.activeScansMu.Unlock()
		cancel()
	}()

	// Run the flow via Conductor
	if err := conductor.RunFlowWithOversight(ctx, flowID, prompt); err != nil {
		if ctx.Err() == context.Canceled {
			log.Printf("[CANCEL] Flow %s was intentionally cancelled", flowID)
			// Status is already updated by handleCancelFlow
		} else {
			log.Printf("[ERROR] Flow %s failed: %v", flowID, err)
			s.queries.UpdateFlowStatus(flowID, models.FlowStatusFailed)
		}
	} else {
		s.queries.UpdateFlowStatus(flowID, models.FlowStatusCompleted)
	}
}

// ============ Pause / Resume ============

func (s *Server) handlePauseFlow(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	// Cancel the active context so the scan goroutine stops.
	s.activeScansMu.Lock()
	cancel, exists := s.activeScans[id]
	if exists {
		delete(s.activeScans, id)
	}
	s.activeScansMu.Unlock()

	if !exists {
		http.Error(w, "flow is not active", http.StatusConflict)
		return
	}
	cancel()

	s.queries.UpdateFlowStatus(id, models.FlowStatusPaused)
	s.queries.CreateFlowEvent(id, string(agent.EventMessage), "Scan paused by user.", nil)
	s.broadcast(agent.Event{
		Type:      agent.EventMessage,
		FlowID:    id.String(),
		Content:   "Scan paused by user.",
		Timestamp: time.Now(),
	})

	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "scan_paused", id.String(), nil, r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleResumeFlow(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	flow, err := s.queries.GetFlow(id)
	if err != nil {
		http.Error(w, "flow not found", http.StatusNotFound)
		return
	}
	if flow.Status != models.FlowStatusPaused {
		http.Error(w, "flow is not paused", http.StatusConflict)
		return
	}

	var body struct {
		Target string `json:"target"`
	}
	// Target is optional — default to the flow's original target.
	_ = json.NewDecoder(r.Body).Decode(&body)
	target := body.Target
	if target == "" {
		target = flow.Target
	}

	s.queries.UpdateFlowStatus(id, models.FlowStatusActive)
	s.queries.CreateFlowEvent(id, string(agent.EventMessage), "Scan resumed by user.", nil)
	s.broadcast(agent.Event{
		Type:      agent.EventMessage,
		FlowID:    id.String(),
		Content:   "Scan resumed by user.",
		Timestamp: time.Now(),
	})

	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "scan_resumed", id.String(), map[string]interface{}{"target": target}, r.RemoteAddr)

	// Restart the agent goroutine.
	go s.runAgent(id, flow.Description, "", 0, 0)

	w.WriteHeader(http.StatusOK)
}

// ============ Remediation ============

func (s *Server) handleFindingSubroute(w http.ResponseWriter, r *http.Request) {
	// /api/findings/{id}/remediation
	path := r.URL.Path[len("/api/findings/"):]
	if len(path) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Split id from sub-path
	parts := splitPath(path)
	if len(parts) == 2 && parts[1] == "remediation" {
		findingID := parts[0]
		switch r.Method {
		case http.MethodPatch:
			s.handleUpdateRemediation(w, r, findingID)
		case http.MethodGet:
			status := s.remediationTracker.GetStatus(findingID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"finding_id": findingID, "status": string(status)})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) handleUpdateRemediation(w http.ResponseWriter, r *http.Request, findingID string) {
	var body struct {
		Status   agent.RemediationStatus `json:"status"`
		Operator string                  `json:"operator"`
		Notes    string                  `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := s.remediationTracker.UpdateStatus(findingID, body.Status, body.Operator, body.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "finding_updated", findingID, map[string]interface{}{
		"status":   body.Status,
		"operator": body.Operator,
	}, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"finding_id": findingID, "status": string(body.Status)})
}

func (s *Server) handleRemediationList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records := s.remediationTracker.GetAll()
	if records == nil {
		records = []*agent.RemediationRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// ============ RBAC / Users ============

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bootstrapping mode: if no users exist, allow all requests.
		if s.rbac.UserCount() == 0 {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, `{"error":"X-API-Key header required"}`, http.StatusUnauthorized)
			return
		}

		user, ok := s.rbac.Authenticate(apiKey)
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), agentUserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type agentContextKey string

const agentUserKey agentContextKey = "agent_user"

func agentUserFromContext(ctx context.Context) *agent.AgentUser {
	u, _ := ctx.Value(agentUserKey).(*agent.AgentUser)
	return u
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require admin if users already exist.
	if s.rbac.UserCount() > 0 {
		user := agentUserFromContext(r.Context())
		if !s.rbac.CanAdmin(user) {
			http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
			return
		}
	}

	var body struct {
		Username string          `json:"username"`
		Role     agent.AgentRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = agent.AgentRoleOperator
	}

	apiKey, err := s.rbac.AddUser(body.Username, body.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	actor := s.actorFromRequest(r)
	s.auditLog.Record(actor, "user_created", body.Username, map[string]interface{}{
		"role": body.Role,
	}, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"username": body.Username,
		"role":     string(body.Role),
		"api_key":  apiKey,
	})
}

// ============ Audit ============

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := r.URL.Query().Get("actor")
	var events []agent.AuditEvent
	if actor != "" {
		events = s.auditLog.GetByActor(actor)
	} else {
		events = s.auditLog.GetAll()
	}
	if events == nil {
		events = []agent.AuditEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// ============ Schedules ============

func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		scans := s.scheduler.ListAll()
		if scans == nil {
			scans = []*agent.ScheduledScan{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scans)

	case http.MethodPost:
		var body struct {
			Target   string `json:"target"`
			Profile  string `json:"profile"`
			CronExpr string `json:"cron_expr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		scan, err := s.scheduler.Add(body.Target, body.Profile, body.CronExpr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(scan)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScheduleByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/schedules/"):]
	if id == "" {
		http.Error(w, "schedule ID required", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.scheduler.Remove(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ============ CI/CD Webhook ============

func (s *Server) handleCICDTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Optional HMAC verification (GitHub webhook format).
	if s.webhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if sig == "" {
			http.Error(w, "missing X-Hub-Signature-256", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if !verifyHMACSHA256([]byte(s.webhookSecret), body, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		Target  string `json:"target"`
		Profile string `json:"profile"`
		Ref     string `json:"ref"`
		Repo    string `json:"repo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if req.Profile == "" {
		req.Profile = "quick"
	}

	name := fmt.Sprintf("CI/CD: %s [%s]", req.Repo, req.Ref)
	flow, err := s.queries.CreateFlow(name, "Triggered by CI/CD pipeline", req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditLog.Record("cicd", "scan_started", flow.ID.String(), map[string]interface{}{
		"target":  req.Target,
		"profile": req.Profile,
		"ref":     req.Ref,
		"repo":    req.Repo,
	}, r.RemoteAddr)

	go s.runAgent(flow.ID, fmt.Sprintf("CI/CD scan for %s at %s", req.Repo, req.Ref), "", 0, 0)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"flow_id": flow.ID.String(),
		"status":  "started",
	})
}

// ============ LLM Mutation ============

// handleMutate accepts a POST request with a payload to mutate and returns LLM-generated variants.
// Body: {"payload":"...","vuln_type":"xss","tech_stack":"php","waf":"cloudflare"}
// Response: {"variants":["...","..."]}
func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Payload   string `json:"payload"`
		VulnType  string `json:"vuln_type"`
		TechStack string `json:"tech_stack"`
		WAF       string `json:"waf"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Payload == "" {
		http.Error(w, "payload is required", http.StatusBadRequest)
		return
	}

	var variants []string
	if s.llmProvider != nil {
		mutator := agent.NewLLMMutator(s.llmProvider, s.cfg.OpenAIModel)
		variants = mutator.Mutate(r.Context(), req.Payload, req.VulnType, strings.TrimSpace(req.TechStack+" "+req.WAF))
	}
	// Fallback: if LLM is unavailable or returned nothing, use rule-based mutation
	if len(variants) == 0 {
		pe := agent.NewPayloadEngine(nil)
		variants = pe.MutatePayload(req.Payload, agent.MutationEncode)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"variants": variants,
	})
}

// ============ Attack Surface Diff ============

func (s *Server) handleSurfaceDiff(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	baselineStr := r.URL.Query().Get("baseline")
	if baselineStr == "" {
		http.Error(w, "baseline query parameter required", http.StatusBadRequest)
		return
	}
	baselineID, err := uuid.Parse(baselineStr)
	if err != nil {
		http.Error(w, "invalid baseline flow ID", http.StatusBadRequest)
		return
	}

	previous := s.surfaceStore.Get(baselineID)
	current := s.surfaceStore.Get(id)

	diff := agent.DiffSurfaces(previous, current)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diff)
}

// ============ Helpers ============

// actorFromRequest extracts the actor name from context or defaults to "anonymous".
func (s *Server) actorFromRequest(r *http.Request) string {
	if u := agentUserFromContext(r.Context()); u != nil {
		return u.Username
	}
	if claims := GetUserFromContext(r.Context()); claims != nil && claims.Username != "" {
		return claims.Username
	}
	return "anonymous"
}

// splitPath splits a URL path segment by "/" returning non-empty parts.
func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// verifyHMACSHA256 checks a GitHub-style "sha256=<hex>" signature.
func verifyHMACSHA256(secret, body []byte, sigHeader string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	expected, err := hex.DecodeString(sigHeader[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), expected)
}

// ============ WebSocket ============

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	log.Printf("[WS] WebSocket client connected (%d total)", len(s.clients))

	// Read loop (handle disconnections)
	go func() {
		defer func() {
			s.clientsMu.Lock()
			delete(s.clients, conn)
			s.clientsMu.Unlock()
			conn.Close()
			log.Printf("[WS] WebSocket client disconnected (%d remaining)", len(s.clients))
		}()

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

func (s *Server) broadcast(event agent.Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	s.broadcastMu.Lock()
	defer s.broadcastMu.Unlock()

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for conn := range s.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("WebSocket broadcast error: %v", err)
			conn.Close()
		}
	}
}

// ============ Report Export Handlers ============

// globalFindingsForFlow returns agent.Finding slice for a specific flow by parsing GlobalFinding records.
func globalFindingsForFlow(allFindings []database.GlobalFinding, flowID uuid.UUID) []*agent.Finding {
	var out []*agent.Finding
	for _, gf := range allFindings {
		if gf.FlowID != flowID {
			continue
		}
		f := &agent.Finding{
			Type:     gf.Title,
			URL:      gf.Target,
			Severity: gf.Severity,
		}
		out = append(out, f)
	}
	return out
}

func (s *Server) handleHTMLReport(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	flow, err := s.queries.GetFlow(id)
	if err != nil {
		http.Error(w, "flow not found", http.StatusNotFound)
		return
	}
	all, _ := s.queries.GetAllFindings()
	agentFindings := globalFindingsForFlow(all, id)
	duration := time.Since(flow.CreatedAt).Round(time.Second).String()
	html := agent.GenerateHTMLReport(flow.Target, id.String(), duration, agentFindings)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"mirage-report-%s.html\"", id.String()[:8]))
	fmt.Fprint(w, html)
}

func (s *Server) handleBurpReport(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	all, _ := s.queries.GetAllFindings()
	agentFindings := globalFindingsForFlow(all, id)
	xmlOut := agent.ExportBurpSuiteXML(agentFindings)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"burp-findings-%s.xml\"", id.String()[:8]))
	fmt.Fprint(w, xmlOut)
}

func (s *Server) handleNucleiReport(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	all, _ := s.queries.GetAllFindings()
	agentFindings := globalFindingsForFlow(all, id)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"nuclei-templates-%s.zip\"", id.String()[:8]))
	zw := zip.NewWriter(w)
	defer zw.Close()
	seen := map[string]bool{}
	for idx, f := range agentFindings {
		key := f.Type + f.URL + f.Parameter
		if seen[key] {
			continue
		}
		seen[key] = true
		tmpl := agent.GenerateNucleiTemplate(f)
		name := fmt.Sprintf("%s-%03d.yaml", strings.ToLower(strings.ReplaceAll(f.Type, " ", "_")), idx)
		fw, err := zw.Create(name)
		if err != nil {
			continue
		}
		fmt.Fprint(fw, tmpl)
	}
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	all, _ := s.queries.GetAllFindings()
	agentFindings := globalFindingsForFlow(all, id)
	type complianceRow struct {
		VulnType   string              `json:"vuln_type"`
		Compliance agent.ComplianceTag `json:"compliance"`
	}
	seen := map[string]bool{}
	var rows []complianceRow
	for _, f := range agentFindings {
		if seen[f.Type] {
			continue
		}
		seen[f.Type] = true
		rows = append(rows, complianceRow{VulnType: f.Type, Compliance: agent.ComplianceTags(f.Type)})
	}
	if rows == nil {
		rows = []complianceRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

// ============ Screenshot Handlers ============

// screenshotMeta is the JSON shape returned for a single screenshot (no data).
type screenshotMeta struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	CapturedAt time.Time `json:"captured_at"`
}

func (s *Server) handleGetScreenshots(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	records := agent.GlobalScreenshots.GetByFlow(id.String())
	out := make([]screenshotMeta, 0, len(records))
	for _, rec := range records {
		out = append(out, screenshotMeta{
			ID:         rec.ID,
			URL:        rec.URL,
			Title:      rec.Title,
			CapturedAt: rec.CapturedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleGetScreenshotImage(w http.ResponseWriter, r *http.Request, _ uuid.UUID, screenshotID string) {
	rec, ok := agent.GlobalScreenshots.GetByID(screenshotID)
	if !ok {
		http.Error(w, "screenshot not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(rec.Data) //nolint:errcheck
}

func (s *Server) handleCaptureScreenshot(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var body struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}
	if body.Title == "" {
		body.Title = body.URL
	}

	rec, err := agent.CaptureAndStore(r.Context(), id.String(), "", body.URL, body.Title)
	if err != nil {
		log.Printf("[SCREENSHOT] capture error for flow %s: %v", id, err)
		http.Error(w, fmt.Sprintf("capture failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(screenshotMeta{
		ID:         rec.ID,
		URL:        rec.URL,
		Title:      rec.Title,
		CapturedAt: rec.CapturedAt,
	})
}

// ============ Middleware ============

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleFlowAuth handles POST/GET/DELETE /api/flows/{id}/auth for session management.
func (s *Server) handleFlowAuth(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	w.Header().Set("Content-Type", "application/json")
	flowKey := id.String()

	switch r.Method {
	case http.MethodPost:
		// Parse request body.
		var req struct {
			Type          string `json:"type"`
			LoginURL      string `json:"login_url"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			UsernameField string `json:"username_field"`
			PasswordField string `json:"password_field"`
			Token         string `json:"token"`
			RawCookies    string `json:"raw_cookies"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		var session *base.AuthSession
		var sessionErr error

		switch req.Type {
		case "form_login":
			usernameField := req.UsernameField
			if usernameField == "" {
				usernameField = "username"
			}
			passwordField := req.PasswordField
			if passwordField == "" {
				passwordField = "password"
			}
			session, sessionErr = base.FormLogin(r.Context(), req.LoginURL, usernameField, passwordField, req.Username, req.Password)
		case "bearer":
			if req.Token == "" {
				http.Error(w, `{"error":"token is required for bearer auth"}`, http.StatusBadRequest)
				return
			}
			session = base.BearerSession(req.Token)
		case "cookie":
			if req.RawCookies == "" {
				http.Error(w, `{"error":"raw_cookies is required for cookie auth"}`, http.StatusBadRequest)
				return
			}
			session = base.CookieSession(req.RawCookies)
		default:
			http.Error(w, `{"error":"unsupported auth type; use form_login, bearer, or cookie"}`, http.StatusBadRequest)
			return
		}

		if sessionErr != nil {
			log.Printf("[auth] flow %s login failed: %v", flowKey, sessionErr)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": sessionErr.Error()})
			return
		}

		s.authMu.Lock()
		s.authSessions[flowKey] = session
		s.authMu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "authenticated",
			"cookies_set": len(session.Cookies),
		})

	case http.MethodGet:
		s.authMu.RLock()
		session, ok := s.authSessions[flowKey]
		s.authMu.RUnlock()

		if !ok {
			http.Error(w, `{"error":"no auth session for this flow"}`, http.StatusNotFound)
			return
		}

		// Return session info without credentials.
		info := map[string]interface{}{
			"type":         session.Type,
			"is_active":    session.IsActive,
			"last_refresh": session.LastRefresh,
			"cookies_set":  len(session.Cookies),
			"headers_set":  len(session.Headers),
			"login_url":    session.LoginURL,
		}
		json.NewEncoder(w).Encode(info)

	case http.MethodDelete:
		s.authMu.Lock()
		delete(s.authSessions, flowKey)
		s.authMu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
