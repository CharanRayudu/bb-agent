package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/threatintel"
)

// registerThreatIntelRoutes adds MITRE ATT&CK / attack chain / risk scoring endpoints.
func (s *Server) registerThreatIntelRoutes() {
	s.mux.HandleFunc("/api/threatintel/attck", s.handleATTCK)
	s.mux.HandleFunc("/api/threatintel/chains", s.handleAttackChains)
	s.mux.HandleFunc("/api/threatintel/risk", s.handleRiskPrioritization)
	s.mux.HandleFunc("/api/threatintel/enrich", s.handleEnrichCVEs)
}

// handleATTCK returns the MITRE ATT&CK coverage matrix for all findings.
// GET /api/threatintel/attck?flow_id=<uuid>
func (s *Server) handleATTCK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	flowID := r.URL.Query().Get("flow_id")
	types := collectFindingTypes(findings, flowID)
	coverage := threatintel.GenerateCoverage(types)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(coverage)
}

// handleAttackChains returns kill-path chains between confirmed findings.
// GET /api/threatintel/chains?flow_id=<uuid>
func (s *Server) handleAttackChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	flowID := r.URL.Query().Get("flow_id")
	types := collectFindingTypes(findings, flowID)
	analysis := threatintel.AnalyzeChains(types)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

// handleRiskPrioritization returns a risk-scored and ranked list of findings.
// GET /api/threatintel/risk?flow_id=<uuid>
func (s *Server) handleRiskPrioritization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	flowID := r.URL.Query().Get("flow_id")

	// Build chain analysis to compute chain depths for each finding type
	types := collectFindingTypes(findings, flowID)
	chainAnalysis := threatintel.AnalyzeChains(types)

	chainDepths := map[string]int{}
	chainImpacts := map[string]string{}
	for _, chain := range chainAnalysis.Chains {
		for i, step := range chain.Steps {
			if i > chainDepths[step.FindingType] {
				chainDepths[step.FindingType] = i
			}
			if chainImpacts[step.FindingType] == "" && step.Impact != "" {
				chainImpacts[step.FindingType] = step.Impact
			}
		}
	}

	// Collect CVE IDs for EPSS enrichment
	var cveIDs []string
	cvssScores := map[string]float64{}
	for _, f := range findings {
		if flowID != "" && f.FlowID.String() != flowID {
			continue
		}
		if cve, ok := f.Metadata["cve"].(string); ok && cve != "" {
			cveIDs = append(cveIDs, cve)
			if cvss, ok := f.Metadata["cvss"].(float64); ok {
				cvssScores[cve] = cvss
			}
		}
	}

	// Best-effort EPSS + KEV enrichment
	epssMap := map[string]*threatintel.EPSSScore{}
	kevSet := map[string]bool{}
	if len(cveIDs) > 0 {
		tiClient := newThreatIntelHTTPClient()
		ctx := r.Context()
		for id, score := range threatintel.FetchEPSS(ctx, tiClient, cveIDs) {
			epssMap[id] = score
		}
		for id := range threatintel.FetchKEV(ctx, tiClient) {
			for _, cve := range cveIDs {
				if cve == id {
					kevSet[id] = true
				}
			}
		}
	}

	// Build FindingInput slice
	inputs := make([]threatintel.FindingInput, 0, len(findings))
	for _, f := range findings {
		if flowID != "" && f.FlowID.String() != flowID {
			continue
		}
		ft := globalFindingType(f)
		conf := 0.75
		if c, ok := f.Metadata["confidence"].(float64); ok {
			conf = c
		}
		cvss := 0.0
		if c, ok := f.Metadata["cvss"].(float64); ok {
			cvss = c
		}
		var cves []string
		if cve, ok := f.Metadata["cve"].(string); ok && cve != "" {
			cves = []string{cve}
		}

		inputs = append(inputs, threatintel.FindingInput{
			Type:       ft,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: conf,
			CVSSScore:  cvss,
			CVEIDs:     cves,
			Target:     f.Target,
			FlowID:     f.FlowID.String(),
		})
	}

	report := threatintel.RankFindings(inputs, chainDepths, chainImpacts, epssMap, kevSet)
	report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// handleEnrichCVEs looks up EPSS and KEV data for provided CVE IDs.
// POST /api/threatintel/enrich  {"cves": ["CVE-2021-44228"], "cvss": {"CVE-...": 9.8}}
func (s *Server) handleEnrichCVEs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CVEs []string           `json:"cves"`
		CVSS map[string]float64 `json:"cvss"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.CVEs) == 0 {
		http.Error(w, "cves array is required", http.StatusBadRequest)
		return
	}

	enriched := threatintel.EnrichCVEs(r.Context(), req.CVEs, req.CVSS)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(enriched),
		"results": enriched,
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func collectFindingTypes(findings []database.GlobalFinding, flowID string) []string {
	typeSet := map[string]bool{}
	for _, f := range findings {
		if flowID != "" && f.FlowID.String() != flowID {
			continue
		}
		ft := globalFindingType(f)
		if ft != "" {
			typeSet[ft] = true
		}
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	return types
}

// globalFindingType extracts a canonical finding type string from a GlobalFinding.
// Priority: metadata["finding_type"] > metadata["type"] > Title > first word of Content.
func globalFindingType(f database.GlobalFinding) string {
	if ft, ok := f.Metadata["finding_type"].(string); ok && ft != "" {
		return ft
	}
	if ft, ok := f.Metadata["type"].(string); ok && ft != "" {
		return ft
	}
	if f.Title != "" {
		// Normalise: "SQL Injection in /login" → "SQL Injection"
		title := f.Title
		if idx := strings.Index(title, " in "); idx > 0 {
			title = title[:idx]
		}
		if idx := strings.Index(title, " at "); idx > 0 {
			title = title[:idx]
		}
		if idx := strings.Index(title, " via "); idx > 0 {
			title = title[:idx]
		}
		return strings.TrimSpace(title)
	}
	return ""
}

func newThreatIntelHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second}
}
