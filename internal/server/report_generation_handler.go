package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/reporter"
	"github.com/bb-agent/mirage/internal/threatintel"
)

func (s *Server) registerReportGenerationRoutes() {
	s.mux.HandleFunc("/api/reports/generate", s.authGate(RoleOperator, s.handleGenerateReport))
	s.mux.HandleFunc("/api/reports/available", s.handleReportAvailable)
}

// handleReportAvailable lets the frontend check whether AI generation is configured.
func (s *Server) handleReportAvailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	gen := reporter.NewGenerator(s.currentLLMProvider(""), s.cfg.OpenAIModel, s.cfg.OpenAITemperature)
	json.NewEncoder(w).Encode(map[string]bool{"available": gen.Available()})
}

// handleGenerateReport streams an AI-written report as SSE.
// POST /api/reports/generate
func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req reporter.ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Template == "" {
		req.Template = "technical"
	}

	// Collect findings
	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Optionally scope to a single flow
	if req.FlowID != "" {
		filtered := findings[:0]
		for _, f := range findings {
			if f.FlowID.String() == req.FlowID {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Build ReportData
	data := reporter.ReportData{
		ScanDate: time.Now().Format("January 2, 2006"),
	}

	// Accumulate severity counts and pick most frequent target
	targetCounts := map[string]int{}
	for _, f := range findings {
		host := f.Target
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		targetCounts[host]++

		data.Findings = append(data.Findings, reporter.FindingSummary{
			Type:     globalFindingType(f),
			Title:    f.Title,
			Target:   f.Target,
			Severity: f.Severity,
		})
		switch f.Severity {
		case "critical":
			data.Critical++
		case "high":
			data.High++
		case "medium":
			data.Medium++
		case "low":
			data.Low++
		default:
			data.Info++
		}
	}
	for host, cnt := range targetCounts {
		if cnt > targetCounts[data.Target] {
			data.Target = host
		}
	}

	// Threat intelligence enrichment
	if req.IncludeThreatIntel {
		types := collectFindingTypes(findings, req.FlowID)
		cov := threatintel.GenerateCoverage(types)
		data.TacticCount = cov.TacticCount
		data.TechniqueCount = cov.TechniqueCount

		chains := threatintel.AnalyzeChains(types)
		data.ChainCount = len(chains.Chains)
	}

	// Monitoring summary
	if req.IncludeMonitoring {
		monitors := s.monitorStore.ListMonitors()
		data.MonitorCount = len(monitors)
		for _, m := range monitors {
			deltas := s.monitorStore.GetDeltas(m.ID)
			if len(deltas) > 0 {
				data.NewSinceBaseline += len(deltas[0].NewFindings)
			}
		}
	}

	// Require SSE-capable response writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	gen := reporter.NewGenerator(s.currentLLMProvider(""), s.cfg.OpenAIModel, s.cfg.OpenAITemperature)
	gen.Generate(r.Context(), req, data, w, flusher.Flush)
}
