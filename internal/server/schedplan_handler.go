package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/schedplan"
)

func (s *Server) registerSchedulePlanRoutes() {
	s.mux.HandleFunc("/api/schedule-plans", s.authGateMethods(RoleOperator, s.handleSchedulePlans, http.MethodPost))
	s.mux.HandleFunc("/api/schedule-plans/", s.authGateMethods(RoleOperator, s.handleSchedulePlan, http.MethodPost, http.MethodPut, http.MethodDelete))
}

func (s *Server) handleSchedulePlans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		list := s.schedPlanStore.List()
		if list == nil {
			list = []*schedplan.Schedule{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"schedules": list,
			"count":     len(list),
			"presets":   schedplan.CronLabel,
		})

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Target      string `json:"target"`
			ProfileID   string `json:"profile_id"`
			ProfileName string `json:"profile_name"`
			Cron        string `json:"cron"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		sc, err := s.schedPlanStore.Create(req.Name, req.Target, req.ProfileID, req.ProfileName, req.Cron)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(sc)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSchedulePlan routes /api/schedule-plans/:id[/toggle|/run]
func (s *Server) handleSchedulePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/schedule-plans/"), "/")
	id := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	switch sub {
	case "toggle":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sc, err := s.schedPlanStore.Toggle(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(sc)

	case "run":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sc, ok := s.schedPlanStore.Get(id)
		if !ok {
			http.Error(w, "schedule not found", http.StatusNotFound)
			return
		}
		s.schedPlanStore.MarkRunning(id)
		go func() {
			s.firePlan(sc)
			s.schedPlanStore.MarkComplete(id, "ok")
		}()
		json.NewEncoder(w).Encode(map[string]string{"status": "triggered"})

	default:
		switch r.Method {
		case http.MethodGet:
			sc, ok := s.schedPlanStore.Get(id)
			if !ok {
				http.Error(w, "schedule not found", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(sc)

		case http.MethodPut:
			var req struct {
				Name        string `json:"name"`
				Target      string `json:"target"`
				ProfileID   string `json:"profile_id"`
				ProfileName string `json:"profile_name"`
				Cron        string `json:"cron"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if err := s.schedPlanStore.Update(id, req.Name, req.Target, req.ProfileID, req.ProfileName, req.Cron); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sc, _ := s.schedPlanStore.Get(id)
			json.NewEncoder(w).Encode(sc)

		case http.MethodDelete:
			if err := s.schedPlanStore.Delete(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
