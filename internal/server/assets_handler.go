package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AssetSummary aggregates per-host data derived from flows and findings.
type AssetSummary struct {
	Host          string         `json:"host"`
	Target        string         `json:"target"`
	FlowID        string         `json:"flow_id"`
	LastScan      time.Time      `json:"last_scan"`
	ScanCount     int            `json:"scan_count"`
	FindingCounts map[string]int `json:"finding_counts"`
	TotalFindings int            `json:"total_findings"`
	RiskScore     int            `json:"risk_score"`
	Status        string         `json:"status"`
}

func hostFromURL(raw string) string {
	if raw == "" {
		return raw
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	return u.Hostname()
}

func calcRiskScore(counts map[string]int) int {
	weights := map[string]int{"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
	penalty := 0
	for sev, w := range weights {
		penalty += counts[sev] * w
	}
	score := 100 - penalty
	if score < 0 {
		return 0
	}
	return score
}

// handleAssets returns a per-host asset inventory derived from flows and findings.
// GET /api/assets
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flows, err := s.queries.ListFlows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build host → AssetSummary from flows
	assetMap := map[string]*AssetSummary{}
	for _, flow := range flows {
		host := hostFromURL(flow.Target)
		if host == "" {
			host = flow.Target
		}
		a, ok := assetMap[host]
		if !ok {
			a = &AssetSummary{
				Host:          host,
				Target:        flow.Target,
				FlowID:        flow.ID.String(),
				LastScan:      flow.CreatedAt,
				FindingCounts: map[string]int{},
				Status:        string(flow.Status),
			}
			assetMap[host] = a
		}
		a.ScanCount++
		if flow.CreatedAt.After(a.LastScan) {
			a.LastScan = flow.CreatedAt
			a.FlowID = flow.ID.String()
			a.Status = string(flow.Status)
		}
	}

	// Attach findings to their host (keyed by flow target)
	for _, f := range findings {
		host := hostFromURL(f.Target)
		if host == "" {
			host = f.Target
		}
		a, ok := assetMap[host]
		if !ok {
			a = &AssetSummary{
				Host:          host,
				Target:        f.Target,
				FlowID:        f.FlowID.String(),
				LastScan:      f.Timestamp,
				FindingCounts: map[string]int{},
				Status:        "completed",
			}
			assetMap[host] = a
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		a.FindingCounts[sev]++
		a.TotalFindings++
	}

	// Compute risk scores and sort by score ascending (most at-risk first)
	assets := make([]AssetSummary, 0, len(assetMap))
	for _, a := range assetMap {
		a.RiskScore = calcRiskScore(a.FindingCounts)
		assets = append(assets, *a)
	}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].RiskScore < assets[j].RiskScore
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"assets":       assets,
		"total_hosts":  len(assets),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleNotificationTest sends a test ping to a webhook URL.
// POST /api/notifications/test
func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"event":   "test",
		"message": "Mirage webhook connectivity test — notifications are working.",
		"source":  "Mirage Autonomous Pentest Platform",
	})

	httpReq, err := http.NewRequest(http.MethodPost, req.URL, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid URL: %v", err), http.StatusBadRequest)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Mirage-Webhook/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("delivery failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Test ping delivered"})
}
