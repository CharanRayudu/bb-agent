package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/copilot"
	"github.com/bb-agent/mirage/internal/threatintel"
)

func (s *Server) registerCopilotRoutes() {
	s.mux.HandleFunc("/api/copilot/sessions", s.authGate(RoleOperator, s.handleCopilotSessions))
	s.mux.HandleFunc("/api/copilot/sessions/", s.authGateMethods(RoleOperator, s.handleCopilotSession, http.MethodDelete))
	s.mux.HandleFunc("/api/copilot/chat", s.authGate(RoleOperator, s.handleCopilotChat))
	s.mux.HandleFunc("/api/copilot/suggestions", s.handleCopilotSuggestions)
	s.mux.HandleFunc("/api/copilot/available", s.handleCopilotAvailable)
}

// handleCopilotAvailable reports whether the shared Codex/OpenAI provider is configured.
func (s *Server) handleCopilotAvailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"available": s.currentLLMProvider("") != nil,
	})
}

// handleCopilotSessions creates a new session.
// POST /api/copilot/sessions → { session_id }
func (s *Server) handleCopilotSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := s.copilotStore.New()
	json.NewEncoder(w).Encode(map[string]string{"session_id": sess.ID})
}

// handleCopilotSession clears a session.
// DELETE /api/copilot/sessions/:id
func (s *Server) handleCopilotSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/api/copilot/sessions/")
	if r.Method == http.MethodDelete {
		s.copilotStore.Delete(id)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}
	if r.Method == http.MethodGet {
		hist := s.copilotStore.History(id)
		json.NewEncoder(w).Encode(map[string]interface{}{"history": hist})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleCopilotChat streams an AI response as SSE.
// POST /api/copilot/chat  { session_id, message }
func (s *Server) handleCopilotChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Message == "" {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	// Auto-create session if not provided
	var sess *copilot.Session
	if req.SessionID == "" {
		sess = s.copilotStore.New()
	} else {
		var ok bool
		sess, ok = s.copilotStore.Get(req.SessionID)
		if !ok {
			sess = s.copilotStore.New()
		}
	}

	// Append user message
	s.copilotStore.Append(sess.ID, copilot.Message{Role: "user", Content: req.Message})
	history := s.copilotStore.History(sess.ID)

	// Build platform context snapshot
	ctx := buildPlatformContext(s)

	// SSE setup
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	// Send session ID first so client can persist it
	fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]string{"type": "session", "session_id": sess.ID}))
	flusher.Flush()

	// Stream from the shared Codex/OpenAI provider.
	reply, err := copilot.Chat(r.Context(), s.currentLLMProvider(""), s.cfg.OpenAIModel, s.cfg.OpenAITemperature, history, ctx, w, flusher.Flush)
	if err == nil && reply != "" {
		s.copilotStore.Append(sess.ID, copilot.Message{Role: "assistant", Content: reply})
	}
}

// handleCopilotSuggestions returns context-aware quick prompts.
// GET /api/copilot/suggestions
func (s *Server) handleCopilotSuggestions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	findings, _ := s.queries.GetAllFindings()

	critical := 0
	high := 0
	targets := map[string]bool{}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		}
		targets[f.Target] = true
	}

	suggestions := []string{
		"What are my most critical vulnerabilities and what should I fix first?",
		"Explain the OWASP Top 10 findings in my scan results",
		"What attack chains are present and how dangerous are they?",
		"Draft an executive summary of the current risk posture",
		"What MITRE ATT&CK techniques are covered by these findings?",
	}

	if critical > 0 {
		suggestions[0] = fmt.Sprintf("I have %d critical findings — what's the fastest path to reduce risk?", critical)
	}
	if high > 0 {
		suggestions = append([]string{
			fmt.Sprintf("Explain the %d high-severity findings and prioritise them by exploitability", high),
		}, suggestions...)
	}
	if len(targets) == 1 {
		for t := range targets {
			suggestions = append(suggestions, fmt.Sprintf("Give me a complete attack narrative for %s", t))
		}
	}

	// Trim to 6
	if len(suggestions) > 6 {
		suggestions = suggestions[:6]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"suggestions": suggestions})
}

// buildPlatformContext assembles a concise platform state summary for the copilot.
func buildPlatformContext(s *Server) string {
	var sb strings.Builder
	sb.WriteString("## Current Platform State\n\n")

	findings, err := s.queries.GetAllFindings()
	if err == nil && len(findings) > 0 {
		counts := map[string]int{}
		targets := map[string]bool{}
		for _, f := range findings {
			counts[f.Severity]++
			targets[f.Target] = true
		}
		sb.WriteString(fmt.Sprintf(
			"**Findings:** %d total — %d critical, %d high, %d medium, %d low, %d info\n",
			len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"],
		))
		sb.WriteString(fmt.Sprintf("**Unique targets:** %d\n\n", len(targets)))

		// Top 8 critical/high findings
		sb.WriteString("**Notable findings:**\n")
		shown := 0
		for _, f := range findings {
			if f.Severity != "critical" && f.Severity != "high" {
				continue
			}
			sb.WriteString(fmt.Sprintf("- [%s] %s (%s) — %s\n",
				strings.ToUpper(f.Severity), f.Title, globalFindingType(f), f.Target))
			shown++
			if shown >= 8 {
				break
			}
		}
		sb.WriteString("\n")

		// ATT&CK coverage
		types := make([]string, 0, len(findings))
		seen := map[string]bool{}
		for _, f := range findings {
			t := globalFindingType(f)
			if !seen[t] {
				types = append(types, t)
				seen[t] = true
			}
		}
		cov := threatintel.GenerateCoverage(types)
		if cov.TacticCount > 0 {
			sb.WriteString(fmt.Sprintf("**ATT&CK coverage:** %d tactics, %d techniques\n", cov.TacticCount, cov.TechniqueCount))
		}

		// Attack chains
		chains := threatintel.AnalyzeChains(types)
		if len(chains.Chains) > 0 {
			sb.WriteString(fmt.Sprintf("**Attack chains:** %d identified\n", len(chains.Chains)))
			if chains.TopChain != nil {
				sb.WriteString(fmt.Sprintf("**Highest-risk chain:** %s (score %.0f)\n", chains.TopChain.Impact, chains.TopChain.Score))
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No findings in the platform yet.\n\n")
	}

	// Monitors
	monitors := s.monitorStore.ListMonitors()
	if len(monitors) > 0 {
		newTotal := 0
		for _, m := range monitors {
			deltas := s.monitorStore.GetDeltas(m.ID)
			if len(deltas) > 0 {
				newTotal += len(deltas[0].NewFindings)
			}
		}
		sb.WriteString(fmt.Sprintf("**Continuous monitoring:** %d active monitors", len(monitors)))
		if newTotal > 0 {
			sb.WriteString(fmt.Sprintf(", %d new findings since baseline", newTotal))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
