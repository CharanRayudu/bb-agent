package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/monitoring"
)

// registerMonitoringRoutes adds continuous monitoring endpoints.
func (s *Server) registerMonitoringRoutes() {
	s.mux.HandleFunc("/api/monitors", s.authGateMethods(RoleOperator, s.handleMonitors, http.MethodPost))
	s.mux.HandleFunc("/api/monitors/", s.authGateMethods(RoleOperator, s.handleMonitor, http.MethodPost, http.MethodPut, http.MethodDelete))
	s.mux.HandleFunc("/api/alerting/channels", s.authGateMethods(RoleOperator, s.handleAlertChannels, http.MethodPost))
	s.mux.HandleFunc("/api/alerting/channels/", s.authGateMethods(RoleOperator, s.handleAlertChannel, http.MethodDelete))
	s.mux.HandleFunc("/api/alerting/test", s.authGate(RoleOperator, s.handleAlertTest))
}

// ── Monitor list / create ─────────────────────────────────────────────────────

// handleMonitors handles GET (list) and POST (create) for /api/monitors.
func (s *Server) handleMonitors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		monitors := s.monitorStore.ListMonitors()
		// Enrich with latest delta summary
		for _, m := range monitors {
			deltas := s.monitorStore.GetDeltas(m.ID)
			if len(deltas) > 0 {
				m.NewSinceBaseline = len(deltas[0].NewFindings)
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"monitors": monitors,
			"count":    len(monitors),
		})

	case http.MethodPost:
		var req struct {
			Name          string   `json:"name"`
			Target        string   `json:"target"`
			Profile       string   `json:"profile"`
			CronExpr      string   `json:"cron_expr"`
			AlertChannels []string `json:"alert_channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		m, err := s.monitorStore.AddMonitor(req.Name, req.Target, req.Profile, req.CronExpr, req.AlertChannels)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Register with the agent scheduler
		if s.scheduler != nil && req.CronExpr != "" {
			sc, schedErr := s.scheduler.Add(req.Target, req.Profile, req.CronExpr)
			if schedErr == nil {
				s.monitorStore.SetSchedulerID(m.ID, sc.ID)
			}
		}
		json.NewEncoder(w).Encode(m)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMonitor handles GET/PUT/DELETE for /api/monitors/:id
// and sub-paths: /api/monitors/:id/baseline, /api/monitors/:id/trigger, /api/monitors/:id/deltas
func (s *Server) handleMonitor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse /api/monitors/<id>[/action]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/monitors/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "monitor ID required", http.StatusBadRequest)
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "baseline":
		s.handleSetBaseline(w, r, id)
	case "trigger":
		s.handleTriggerScan(w, r, id)
	case "deltas":
		s.handleGetDeltas(w, r, id)
	default:
		s.handleMonitorCRUD(w, r, id)
	}
}

func (s *Server) handleMonitorCRUD(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		m, ok := s.monitorStore.GetMonitor(id)
		if !ok {
			http.Error(w, "monitor not found", http.StatusNotFound)
			return
		}
		deltas := s.monitorStore.GetDeltas(id)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"monitor":       m,
			"recent_deltas": deltas,
		})

	case http.MethodPut:
		var req struct {
			Name          string                   `json:"name"`
			Profile       string                   `json:"profile"`
			CronExpr      string                   `json:"cron_expr"`
			AlertChannels []string                 `json:"alert_channels"`
			Status        monitoring.MonitorStatus `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.monitorStore.UpdateMonitor(id, req.Name, req.Profile, req.CronExpr, req.AlertChannels, req.Status); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	case http.MethodDelete:
		if err := s.monitorStore.DeleteMonitor(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSetBaseline snapshots the current findings for a target as the baseline.
// POST /api/monitors/:id/baseline
func (s *Server) handleSetBaseline(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, ok := s.monitorStore.GetMonitor(id)
	if !ok {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	summaries := findingsToSummaries(findings, m.Target)
	bl := monitoring.BuildBaseline(id, summaries)
	s.monitorStore.SetBaseline(id, bl)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"baseline_at":   bl.SnapshotAt.UTC().Format(time.RFC3339),
		"finding_count": len(summaries),
	})
}

// handleTriggerScan manually triggers a scan for a monitor.
// POST /api/monitors/:id/trigger
func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, ok := s.monitorStore.GetMonitor(id)
	if !ok {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}

	if s.scheduler != nil {
		go func() {
			// Re-use the scheduler's trigger function
			s.schedulerTrigger(m.Target, m.Profile)
			s.monitorStore.MarkScanned(id)

			// After scan completes, compute delta
			s.computeAndDispatchDelta(id, m)
		}()
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":     "triggered",
		"monitor_id": id,
		"target":     m.Target,
	})
}

// handleGetDeltas returns the delta history for a monitor.
// GET /api/monitors/:id/deltas
func (s *Server) handleGetDeltas(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	deltas := s.monitorStore.GetDeltas(id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"monitor_id": id,
		"deltas":     deltas,
		"count":      len(deltas),
	})
}

// computeAndDispatchDelta computes a delta for a monitor and fires alerts.
func (s *Server) computeAndDispatchDelta(monitorID string, m *monitoring.Monitor) {
	findings, err := s.queries.GetAllFindings()
	if err != nil {
		return
	}

	summaries := findingsToSummaries(findings, m.Target)
	bl, hasBaseline := s.monitorStore.GetBaseline(monitorID)
	if !hasBaseline {
		// Auto-set baseline on first scan
		bl = monitoring.BuildBaseline(monitorID, summaries)
		s.monitorStore.SetBaseline(monitorID, bl)
		return
	}

	delta := monitoring.ComputeDelta(monitorID, bl, summaries)
	if len(delta.NewFindings)+len(delta.ResolvedFindings)+len(delta.Regressions) == 0 {
		return // no change
	}

	s.monitorStore.AppendDelta(monitorID, delta)

	// Dispatch alerts if the monitor has channels configured
	if len(m.AlertChannels) > 0 && s.alertDispatcher != nil {
		allNew := append(delta.NewFindings, delta.Regressions...)
		sev := monitoring.HighestSeverity(allNew)
		event := monitoring.AlertEvent{
			MonitorID:   monitorID,
			MonitorName: m.Name,
			Target:      m.Target,
			Delta:       delta,
			Timestamp:   time.Now(),
			Severity:    sev,
		}
		_ = s.alertDispatcher.Dispatch(context.Background(), event, m.AlertChannels)
	}
}

// ── Alert channels ────────────────────────────────────────────────────────────

func (s *Server) handleAlertChannels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		channels := s.monitorStore.GetChannels()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"channels": channels,
			"count":    len(channels),
		})

	case http.MethodPost:
		var ch monitoring.AlertChannel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if ch.URL == "" {
			http.Error(w, "url is required", http.StatusBadRequest)
			return
		}
		created := s.monitorStore.AddChannel(ch)
		json.NewEncoder(w).Encode(created)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAlertChannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/api/alerting/channels/")

	if r.Method == http.MethodDelete {
		s.monitorStore.DeleteChannel(id)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleAlertTest fires a test alert to verify channel connectivity.
// POST /api/alerting/test  {"channel_id": "..."}
func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChannelID string `json:"channel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if s.alertDispatcher == nil {
		http.Error(w, "alert dispatcher not configured", http.StatusServiceUnavailable)
		return
	}

	if err := s.alertDispatcher.SendTest(r.Context(), req.ChannelID); err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func findingsToSummaries(findings []database.GlobalFinding, targetFilter string) []monitoring.FindingSummary {
	var out []monitoring.FindingSummary
	for _, f := range findings {
		if targetFilter != "" && !strings.Contains(f.Target, targetFilter) {
			continue
		}
		ft := globalFindingType(f)
		parameter, _ := f.Metadata["parameter"].(string)
		fp := monitoring.FingerprintFinding(ft, f.Target, parameter)

		conf := 0.75
		if c, ok := f.Metadata["confidence"].(float64); ok {
			conf = c
		}

		out = append(out, monitoring.FindingSummary{
			Fingerprint: fp,
			Type:        ft,
			Title:       f.Title,
			Target:      f.Target,
			Severity:    f.Severity,
			Confidence:  conf,
			FlowID:      f.FlowID.String(),
		})
	}
	return out
}
