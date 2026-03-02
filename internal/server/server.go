package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

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
	clients   map[*websocket.Conn]bool
	clientsMu sync.RWMutex

	// Agent
	orchestrator *agent.Orchestrator
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
		clients: make(map[*websocket.Conn]bool),
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// API routes
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/models", s.handleModels)
	s.mux.HandleFunc("/api/flows", s.handleFlows)
	s.mux.HandleFunc("/api/flows/", s.handleFlow)
	s.mux.HandleFunc("/api/flows/create", s.handleCreateFlow)

	// WebSocket
	s.mux.HandleFunc("/ws", s.handleWebSocket)

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

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	// Simple router for /api/flows/{id} vs /api/flows/{id}/events
	path := r.URL.Path[len("/api/flows/"):]

	// Check if this is the events sub-route
	if len(path) > 36 && path[36:] == "/events" {
		idStr := path[:36]
		id, err := uuid.Parse(idStr)
		if err != nil {
			http.Error(w, "Invalid flow ID", http.StatusBadRequest)
			return
		}
		s.handleFlowEvents(w, r, id)
		return
	}

	// Otherwise, handle regular FlowByID
	id, err := uuid.Parse(path)
	if err != nil {
		http.Error(w, "Invalid flow ID", http.StatusBadRequest)
		return
	}
	s.handleFlowByID(w, r, id)
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

	// Load tasks
	tasks, err := s.queries.GetTasksByFlow(id)
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

	// 1. Try to fetch from new flow_events table first
	events, err := s.queries.GetFlowEvents(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Initialize as empty slice (not nil) to ensure JSON is []
	if events == nil {
		events = []database.EventWithTimestamp{}
	}

	// 2. If no events in flow_events, fall back to reconstructing from actions table (backward compatibility)
	if len(events) == 0 {
		actions, err := s.queries.GetActionsByFlow(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Map DB Actions to WebSocket-style Events
		for _, a := range actions {
			toolName := ""
			sType := string(a.Type)
			if sType == "command" {
				toolName = "execute_command"
			} else if sType == "analyze" || sType == "llm_call" {
				toolName = "think"
			} else if sType == "report" {
				toolName = "report_findings"
			} else if sType == "search" {
				toolName = "search_nuclei_templates"
			} else {
				toolName = sType
			}

			// Reconstruct the Tool Call Event
			args := a.Input
			isJSON := strings.HasPrefix(strings.TrimSpace(args), "{")

			// Ensure args is a JSON string of an object
			if toolName == "execute_command" && !isJSON {
				args = fmt.Sprintf(`{"command": %q}`, args)
			} else if toolName == "think" && !isJSON {
				args = fmt.Sprintf(`{"thought": %q}`, args)
			} else if !isJSON {
				args = fmt.Sprintf(`{"input": %q}`, args)
			}

			events = append(events, database.EventWithTimestamp{
				Type:      "tool_call",
				Content:   fmt.Sprintf("Calling %s", toolName),
				Timestamp: a.CreatedAt,
				Metadata: map[string]interface{}{
					"tool": toolName,
					"args": args,
				},
			})

			// Reconstruct the Tool Result Event
			events = append(events, database.EventWithTimestamp{
				Type:      "tool_result",
				Content:   a.Output,
				Timestamp: a.CreatedAt,
				Metadata: map[string]interface{}{
					"tool":   toolName,
					"status": a.Status,
				},
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// CreateFlowRequest is the JSON body for creating a new flow
type CreateFlowRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Model       string `json:"model"`
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
	go s.runAgent(flow.ID, req.Description, req.Model)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

func (s *Server) runAgent(flowID uuid.UUID, prompt string, selectedModel string) {
	// Create Docker sandbox
	sandbox, err := docker.NewSandbox(s.cfg.DockerHost, s.cfg.SandboxImage)
	if err != nil {
		log.Printf("❌ Failed to create sandbox: %v", err)
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
	log.Printf("🧠 Using model: %s", model)

	// Create LLM provider — prefer Codex OAuth, fall back to API key
	var provider llm.Provider

	codexAuth := llm.NewCodexTokenProvider(s.cfg.CodexHome)
	if codexAuth.IsAvailable() {
		log.Println("🔐 Using Codex CLI OAuth for LLM authentication")
		provider = llm.NewOpenAIProviderWithCodex(codexAuth, model, s.cfg.OpenAITemperature)
	} else if s.cfg.OpenAIAPIKey != "" {
		log.Println("🔑 Using OpenAI API key for LLM authentication")
		provider = llm.NewOpenAIProvider(s.cfg.OpenAIAPIKey, model, s.cfg.OpenAITemperature)
	} else {
		errMsg := "No LLM authentication available. Run 'codex login' or set OPENAI_API_KEY"
		log.Printf("❌ %s", errMsg)
		s.queries.UpdateFlowStatus(flowID, models.FlowStatusFailed)
		s.broadcast(agent.Event{
			Type:    agent.EventError,
			FlowID:  flowID.String(),
			Content: errMsg,
		})
		return
	}

	// Create tool registry
	registry := tools.NewRegistry(sandbox)

	// Create orchestrator
	orchestrator := agent.NewOrchestrator(provider, registry, s.db)
	orchestrator.SetEventHandler(func(event agent.Event) {
		s.broadcast(event)
	})

	// Run the flow
	ctx := context.Background()
	if err := orchestrator.RunFlow(ctx, flowID, prompt); err != nil {
		log.Printf("❌ Flow %s failed: %v", flowID, err)
		s.queries.UpdateFlowStatus(flowID, models.FlowStatusFailed)
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

	log.Printf("🔌 WebSocket client connected (%d total)", len(s.clients))

	// Read loop (handle disconnections)
	go func() {
		defer func() {
			s.clientsMu.Lock()
			delete(s.clients, conn)
			s.clientsMu.Unlock()
			conn.Close()
			log.Printf("🔌 WebSocket client disconnected (%d remaining)", len(s.clients))
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

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for conn := range s.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("WebSocket write error: %v", err)
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
