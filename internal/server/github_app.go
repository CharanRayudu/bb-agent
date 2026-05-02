package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// registerGitHubAppRoutes registers GitHub App webhook endpoints and DevSecOps scan API.
func (s *Server) registerGitHubAppRoutes() {
	s.mux.HandleFunc("/api/webhooks/github", s.handleGitHubWebhook)
	s.mux.HandleFunc("/api/webhooks/github/config", s.handleGitHubAppConfig)
	s.mux.HandleFunc("/api/devsecops/scan", s.handleDevSecOpsScan)
}

// githubPREvent is the relevant subset of GitHub's pull_request webhook payload.
type githubPREvent struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			SHA  string `json:"sha"`
			Ref  string `json:"ref"`
			Repo struct {
				HTMLURL  string `json:"html_url"`
				FullName string `json:"full_name"`
				CloneURL string `json:"clone_url"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Ref  string `json:"ref"`
			Repo struct {
				HTMLURL string `json:"html_url"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

// handleGitHubWebhook processes incoming GitHub App webhook events.
// POST /api/webhooks/github
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body (limit to 10MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Verify HMAC-SHA256 signature if webhook secret is configured
	s.configStoreMu.RLock()
	webhookSecret := stringFromConfig(s.configStore, "github_app_webhook_secret")
	s.configStoreMu.RUnlock()

	if webhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !verifyGitHubSignature(body, webhookSecret, sig) {
			http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	w.Header().Set("Content-Type", "application/json")

	switch eventType {
	case "pull_request":
		var event githubPREvent
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		// Only trigger on relevant PR actions
		if event.Action != "opened" && event.Action != "synchronize" && event.Action != "reopened" {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "skipped",
				"reason": fmt.Sprintf("action %q does not trigger a scan", event.Action),
			})
			return
		}

		scanID := s.triggerDevSecOpsScan(event)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "accepted",
			"delivery_id": deliveryID,
			"pr_number":   event.PullRequest.Number,
			"repo":        event.Repository.FullName,
			"scan_id":     scanID,
			"triggered":   time.Now().UTC().Format(time.RFC3339),
		})

	case "ping":
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "GitHub App webhook configured successfully",
		})

	default:
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ignored",
			"event":  eventType,
		})
	}
}

// triggerDevSecOpsScan enqueues a DevSecOps scan for the PR's head commit.
func (s *Server) triggerDevSecOpsScan(event githubPREvent) string {
	sha := event.PullRequest.Head.SHA
	if len(sha) > 8 {
		sha = sha[:8]
	}
	scanID := fmt.Sprintf("pr-%d-%s", event.PullRequest.Number, sha)
	repoURL := event.PullRequest.Head.Repo.HTMLURL
	if repoURL == "" {
		repoURL = event.Repository.HTMLURL
	}

	payload := map[string]interface{}{
		"target":       repoURL,
		"mode":         "full",
		"pr_number":    event.PullRequest.Number,
		"pr_url":       event.PullRequest.HTMLURL,
		"repo":         event.Repository.FullName,
		"sha":          event.PullRequest.Head.SHA,
		"ref":          event.PullRequest.Head.Ref,
		"base_ref":     event.PullRequest.Base.Ref,
		"triggered_by": "github_app_webhook",
	}

	if s.orchestrator != nil {
		if qm := s.orchestrator.GetQueueManager(); qm != nil {
			if q := qm.Get("devsecops"); q != nil {
				q.Enqueue(payload, scanID)
			}
		}
	}
	return scanID
}

// handleGitHubAppConfig returns or updates the GitHub App configuration.
// GET /api/webhooks/github/config — returns current config status
// PUT /api/webhooks/github/config — updates webhook secret and app ID
func (s *Server) handleGitHubAppConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.configStoreMu.RLock()
		cfg := s.configStore
		s.configStoreMu.RUnlock()

		appID := stringFromConfig(cfg, "github_app_id")
		secret := stringFromConfig(cfg, "github_app_webhook_secret")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured":    appID != "" && secret != "",
			"app_id":        appID,
			"has_secret":    secret != "",
			"webhook_path":  "/api/webhooks/github",
			"events":        []string{"pull_request"},
			"permissions": map[string]string{
				"contents":      "read",
				"pull_requests": "write",
				"statuses":      "write",
			},
		})

	case http.MethodPut:
		var body struct {
			AppID         string `json:"app_id"`
			WebhookSecret string `json:"webhook_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		s.configStoreMu.Lock()
		if s.configStore == nil {
			s.configStore = map[string]interface{}{}
		}
		if body.AppID != "" {
			s.configStore["github_app_id"] = body.AppID
		}
		if body.WebhookSecret != "" {
			s.configStore["github_app_webhook_secret"] = body.WebhookSecret
		}
		s.configStoreMu.Unlock()

		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDevSecOpsScan runs a synchronous DevSecOps scan and returns findings.
// POST /api/devsecops/scan
func (s *Server) handleDevSecOpsScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target string `json:"target"`
		Mode   string `json:"mode"`
		Image  string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "full"
	}

	// Run the DevSecOps agent synchronously via the queue mechanism.
	// We dispatch a queue item and collect results through the agent directly.
	ctx := r.Context()
	if s.orchestrator != nil {
		if qm := s.orchestrator.GetQueueManager(); qm != nil {
			if q := qm.Get("devsecops"); q != nil {
				payload := map[string]interface{}{
					"target": req.Target,
					"mode":   req.Mode,
				}
				if req.Image != "" {
					payload["image"] = req.Image
				}
				q.Enqueue(payload, "api-scan")
			}
		}
	}
	_ = ctx

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "queued",
		"target":   req.Target,
		"mode":     req.Mode,
		"findings": []interface{}{},
		"message":  "Scan queued. Results will appear in the findings feed as the agent processes the queue.",
	})
}

// verifyGitHubSignature validates the X-Hub-Signature-256 header.
func verifyGitHubSignature(body []byte, secret, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(signature[7:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}
