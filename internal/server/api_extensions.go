package server

import (
	"encoding/json"
	"net/http"

	"github.com/bb-agent/mirage/internal/knowledge"
)

// registerExtendedRoutes adds new API endpoints for the extended architecture.
func (s *Server) registerExtendedRoutes() {
	// Auth routes
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/keys", s.handleAPIKeys)

	// Knowledge graph API
	s.mux.HandleFunc("/api/knowledge/graph", s.handleKnowledgeGraph)

	// Configuration API
	s.mux.HandleFunc("/api/config", s.handleConfig)

	// Schema migrations info
	s.mux.HandleFunc("/api/system/migrations", s.handleMigrations)
}

func (s *Server) handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.knowledgeGraphMu.RLock()
	nodes := s.knowledgeGraph.AllNodes()
	edges := s.knowledgeGraph.AllEdges()
	s.knowledgeGraphMu.RUnlock()

	// JSON-encode as non-null arrays even when empty
	nodesOut := nodes
	if nodesOut == nil {
		nodesOut = make([]*knowledge.KGNode, 0)
	}
	edgesOut := edges
	if edgesOut == nil {
		edgesOut = make([]*knowledge.KGEdge, 0)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": nodesOut,
		"edges": edgesOut,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.configStoreMu.RLock()
		cfg := s.configStore
		s.configStoreMu.RUnlock()
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		s.configStoreMu.Lock()
		s.configStore = body
		s.configStoreMu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleMigrations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"migrations": []interface{}{},
	})
}
