package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/posture"
	"github.com/bb-agent/mirage/internal/remediation"
)

func (s *Server) registerPostureRoutes() {
	s.mux.HandleFunc("/api/posture", s.handlePosture)
	s.mux.HandleFunc("/api/posture/history", s.handlePostureHistory)
}

// handlePosture computes and returns the current security posture snapshot.
// GET /api/posture
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate finding data
	counts := map[string]int{}
	targets := map[string]bool{}
	typeSet := map[string]bool{}
	openCritical, openHigh := 0, 0

	for _, f := range findings {
		counts[f.Severity]++
		host := f.Target
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		targets[host] = true
		ft := globalFindingType(f)
		typeSet[ft] = true

		// Count open (untracked) critical/high
		if existing := s.remStore.ByFindingID(f.ID); existing == nil {
			if f.Severity == "critical" {
				openCritical++
			} else if f.Severity == "high" {
				openHigh++
			}
		}
	}

	findingTypes := make([]string, 0, len(typeSet))
	for t := range typeSet {
		findingTypes = append(findingTypes, t)
	}

	// Remediation stats
	remItems := s.remStore.List("")
	remMetrics := remediation.ComputeMetrics(remItems)

	// Monitor count
	monitors := s.monitorStore.ListMonitors()

	in := posture.Input{
		FindingCounts:   counts,
		FindingTypes:    findingTypes,
		RemItems:        len(remItems),
		RemFixed:        remMetrics.ByStatus["fixed"] + remMetrics.ByStatus["verified"],
		SLABreached:     remMetrics.SLABreached,
		SLACompliant:    remMetrics.SLACompliant,
		MonitorCount:    len(monitors),
		UniqueTargets:   len(targets),
		OpenCritical:    openCritical,
		OpenHigh:        openHigh,
	}

	snap := posture.Compute(in)

	// Persist snapshot to history (skip if called too frequently — only store once per hour)
	history := s.postureHistory.All()
	shouldStore := len(history) == 0 || snap.Timestamp.Sub(history[len(history)-1].Timestamp).Minutes() >= 60
	if shouldStore {
		s.postureHistory.Push(snap)
	}

	json.NewEncoder(w).Encode(snap)
}

// handlePostureHistory returns the rolling history of posture snapshots.
// GET /api/posture/history
func (s *Server) handlePostureHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	history := s.postureHistory.All()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"history": history,
		"count":   len(history),
	})
}
