package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/profiles"
)

func (s *Server) registerProfilesRoutes() {
	s.mux.HandleFunc("/api/profiles", s.handleProfiles)
	s.mux.HandleFunc("/api/profiles/", s.handleProfile)
}

// handleProfiles — GET list, POST create
func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		category := r.URL.Query().Get("category")
		list := s.profileStore.List(category)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"profiles": list,
			"count":    len(list),
		})

	case http.MethodPost:
		var req struct {
			Name        string                  `json:"name"`
			Description string                  `json:"description"`
			Category    string                  `json:"category"`
			Color       string                  `json:"color"`
			Agents      []profiles.AgentConfig  `json:"agents"`
			Tags        []string                `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Category == "" {
			req.Category = "custom"
		}
		if req.Color == "" {
			req.Color = "#67e8f9"
		}
		p, err := s.profileStore.Create(req.Name, req.Description, req.Category, req.Color, req.Agents, req.Tags)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(p)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProfile handles /api/profiles/:id[/clone|/use]
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/profiles/"), "/")
	id := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	switch sub {
	case "clone":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p, err := s.profileStore.Clone(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(p)

	case "use":
		// POST /api/profiles/:id/use — increments use count
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.profileStore.IncrementUseCount(id)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		switch r.Method {
		case http.MethodGet:
			p, ok := s.profileStore.Get(id)
			if !ok {
				http.Error(w, "profile not found", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(p)

		case http.MethodPut:
			var req struct {
				Name        string                 `json:"name"`
				Description string                 `json:"description"`
				Color       string                 `json:"color"`
				Agents      []profiles.AgentConfig `json:"agents"`
				Tags        []string               `json:"tags"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if err := s.profileStore.Update(id, req.Name, req.Description, req.Color, req.Agents, req.Tags); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			p, _ := s.profileStore.Get(id)
			json.NewEncoder(w).Encode(p)

		case http.MethodDelete:
			if err := s.profileStore.Delete(id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
