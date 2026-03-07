package server

import (
	"encoding/json"
	"net/http"
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": []interface{}{},
		"edges": []interface{}{},
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": map[string]interface{}{
				"openai": map[string]interface{}{"enabled": true, "model": "gpt-4o"},
			},
		})

	case http.MethodPut:
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
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
