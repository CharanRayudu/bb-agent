package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/notify"
)

func (s *Server) registerNotifyRoutes() {
	s.mux.HandleFunc("/api/notify/channels", s.handleNotifyChannels)
	s.mux.HandleFunc("/api/notify/channels/", s.handleNotifyChannel)
	s.mux.HandleFunc("/api/notify/events", s.handleNotifyEvents)
}

func (s *Server) handleNotifyChannels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		list := s.notifyStore.List()
		if list == nil {
			list = []*notify.Channel{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"channels": list,
			"count":    len(list),
			"events":   notify.SupportedEvents,
		})

	case http.MethodPost:
		var req struct {
			Name   string               `json:"name"`
			Type   notify.ChannelType   `json:"type"`
			Config notify.ChannelConfig `json:"config"`
			Events []string             `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		ch, err := s.notifyStore.Create(req.Name, req.Type, req.Config, req.Events)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ch)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNotifyChannel routes /api/notify/channels/:id[/test]
func (s *Server) handleNotifyChannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/notify/channels/"), "/")
	id := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	if sub == "test" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.notifyDispatcher.Test(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		ch, ok := s.notifyStore.Get(id)
		if !ok {
			http.Error(w, "channel not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(ch)

	case http.MethodPut:
		var req struct {
			Name    string               `json:"name"`
			Config  notify.ChannelConfig `json:"config"`
			Events  []string             `json:"events"`
			Enabled bool                 `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.notifyStore.Update(id, req.Name, req.Config, req.Events, req.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ch, _ := s.notifyStore.Get(id)
		json.NewEncoder(w).Encode(ch)

	case http.MethodDelete:
		if err := s.notifyStore.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNotifyEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": notify.SupportedEvents,
	})
}
