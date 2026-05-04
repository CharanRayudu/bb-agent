package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/database"
)

func (s *Server) registerVulnIntelRoutes() {
	s.mux.HandleFunc("/api/findings/stats", s.handleFindingStats)
	s.mux.HandleFunc("/api/findings/search", s.handleFindingSearch)
	s.mux.HandleFunc("/api/findings/export", s.handleFindingExport)
}

// ── /api/findings/stats ────────────────────────────────────────────────────────

type findingStats struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	TopTypes   []nameCount    `json:"top_types"`
	TopTargets []nameCount    `json:"top_targets"`
	Trend      []dayCount     `json:"trend"` // last 30 days
}

type nameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type dayCount struct {
	Date  string `json:"date"` // YYYY-MM-DD
	Count int    `json:"count"`
}

func (s *Server) handleFindingStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if !s.queries.HasDB() {
		json.NewEncoder(w).Encode(emptyStats())
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		json.NewEncoder(w).Encode(emptyStats())
		return
	}

	json.NewEncoder(w).Encode(computeStats(findings))
}

func computeStats(findings []database.GlobalFinding) findingStats {
	bySev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	typeMap := map[string]int{}
	targetMap := map[string]int{}
	dayMap := map[string]int{}

	cutoff := time.Now().AddDate(0, 0, -29).Truncate(24 * time.Hour)

	for _, f := range findings {
		bySev[f.Severity]++
		typeMap[f.Title]++
		targetMap[f.Target]++
		if !f.Timestamp.Before(cutoff) {
			key := f.Timestamp.Format("2006-01-02")
			dayMap[key]++
		}
	}

	// Top types (max 15)
	topTypes := sortedTop(typeMap, 15)

	// Top targets (max 10)
	topTargets := sortedTop(targetMap, 10)

	// Trend: fill every day for last 30 days even if 0
	trend := make([]dayCount, 30)
	for i := range trend {
		d := time.Now().AddDate(0, 0, -(29 - i)).Format("2006-01-02")
		trend[i] = dayCount{Date: d, Count: dayMap[d]}
	}

	return findingStats{
		Total:      len(findings),
		BySeverity: bySev,
		TopTypes:   topTypes,
		TopTargets: topTargets,
		Trend:      trend,
	}
}

func sortedTop(m map[string]int, limit int) []nameCount {
	out := make([]nameCount, 0, len(m))
	for k, v := range m {
		out = append(out, nameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func emptyStats() findingStats {
	return findingStats{
		BySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
		TopTypes:   []nameCount{},
		TopTargets: []nameCount{},
		Trend:      []dayCount{},
	}
}

// ── /api/findings/search ───────────────────────────────────────────────────────

func (s *Server) handleFindingSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	q := strings.ToLower(r.URL.Query().Get("q"))
	sevFilter := strings.ToLower(r.URL.Query().Get("severity"))
	targetFilter := strings.ToLower(r.URL.Query().Get("target"))
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 || limit > 200 {
		limit = 50
	}

	var fromT, toT time.Time
	if fromStr != "" {
		fromT, _ = time.Parse("2006-01-02", fromStr)
	}
	if toStr != "" {
		toT, _ = time.Parse("2006-01-02", toStr)
		toT = toT.Add(24 * time.Hour)
	}

	if !s.queries.HasDB() {
		json.NewEncoder(w).Encode(map[string]interface{}{"findings": []interface{}{}, "total": 0, "page": page, "limit": limit, "pages": 0})
		return
	}

	findings, err := s.queries.GetAllFindings()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"findings": []interface{}{}, "total": 0, "page": page, "limit": limit, "pages": 0})
		return
	}

	var filtered []database.GlobalFinding
	for _, f := range findings {
		if sevFilter != "" && f.Severity != sevFilter {
			continue
		}
		if targetFilter != "" && !strings.Contains(strings.ToLower(f.Target), targetFilter) {
			continue
		}
		if !fromT.IsZero() && f.Timestamp.Before(fromT) {
			continue
		}
		if !toT.IsZero() && f.Timestamp.After(toT) {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(f.Title + " " + f.Target + " " + f.Content)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		filtered = append(filtered, f)
	}

	total := len(filtered)
	start := (page - 1) * limit
	if start >= total {
		filtered = nil
	} else {
		end := start + limit
		if end > total {
			end = total
		}
		filtered = filtered[start:end]
	}
	if filtered == nil {
		filtered = []database.GlobalFinding{}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": filtered,
		"total":    total,
		"page":     page,
		"limit":    limit,
		"pages":    (total + limit - 1) / limit,
	})
}

// ── /api/findings/export ───────────────────────────────────────────────────────

func (s *Server) handleFindingExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var findings []database.GlobalFinding
	if s.queries.HasDB() {
		var err error
		findings, err = s.queries.GetAllFindings()
		if err != nil {
			http.Error(w, "failed to fetch findings", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"mirage-findings.csv\"")

	cw := csv.NewWriter(w)
	cw.Write([]string{"ID", "Flow", "Target", "Severity", "Title", "Timestamp"}) //nolint:errcheck
	for _, f := range findings {
		cw.Write([]string{ //nolint:errcheck
			f.ID,
			f.FlowName,
			f.Target,
			f.Severity,
			f.Title,
			f.Timestamp.Format(time.RFC3339),
		})
	}
	cw.Flush()
}
