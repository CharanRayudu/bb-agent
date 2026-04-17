package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/agent"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/docker"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

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
}

// New creates a new server instance
func New(cfg *config.Config, db *sql.DB) *Server {
	s := &Server{
		cfg:     cfg,
		db:      db,
		queries: database.NewQueries(db),
		mux:     http.NewServeMux(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients:     make(map[*websocket.Conn]bool),
		activeScans: make(map[uuid.UUID]context.CancelFunc),
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// API routes -- register more specific patterns first so /api/flows/{id} and /api/flows/create
	// are handled by handleFlow/handleCreateFlow, not handleFlows (which only allows GET and would return 405 for DELETE)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/models", s.handleModels)
	s.mux.HandleFunc("/api/findings", s.handleFindings)
	s.mux.HandleFunc("/api/flows/create", s.handleCreateFlow)
	s.mux.HandleFunc("/api/flows/", s.handleFlow)
	s.mux.HandleFunc("/api/flows", s.handleFlows)

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

	w.WriteHeader(http.StatusOK)
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

// CreateFlowRequest is the JSON body for creating a new flow
type CreateFlowRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Target       string `json:"target"`
	Model        string `json:"model"`
	Timeout      int    `json:"timeout"`        // Total scan timeout in minutes
	AgentTimeout int    `json:"agent_timeout"`  // Per-agent timeout in minutes
	CavemanMode  bool   `json:"caveman_mode"`   // Skip LLM planning; dispatch all specialists directly
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

	// Initialize the agent and run the flow asynchronously
	go s.runAgent(flow.ID, req.Description, req.Model, req.Timeout, req.AgentTimeout, req.CavemanMode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

func (s *Server) runAgent(flowID uuid.UUID, prompt string, selectedModel string, timeout int, agentTimeout int, cavemanMode bool) {
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
	if cavemanMode {
		orchestrator.SetCavemanMode(true)
		log.Println("[CAVEMAN] Caveman mode enabled: bypassing LLM planning")
	}
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
