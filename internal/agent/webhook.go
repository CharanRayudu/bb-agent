package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WebhookConfig holds configuration for a single webhook endpoint.
type WebhookConfig struct {
	URL    string
	Secret string   // HMAC-SHA256 signing secret
	Events []string // "critical_finding", "scan_complete", "high_finding"
}

// WebhookNotifier dispatches webhook notifications to configured endpoints.
type WebhookNotifier struct {
	configs []WebhookConfig
	client  *http.Client
}

// NewWebhookNotifier creates a WebhookNotifier with the provided configs.
func NewWebhookNotifier(configs []WebhookConfig) *WebhookNotifier {
	return &WebhookNotifier{
		configs: configs,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// webhookFindingPayload is the JSON body sent for a finding notification.
type webhookFindingPayload struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Finding   struct {
		Type       string                 `json:"type"`
		URL        string                 `json:"url"`
		Parameter  string                 `json:"parameter,omitempty"`
		Payload    string                 `json:"payload,omitempty"`
		Severity   string                 `json:"severity"`
		Confidence float64                `json:"confidence"`
		Evidence   map[string]interface{} `json:"evidence,omitempty"`
		Method     string                 `json:"method,omitempty"`
		Agent      string                 `json:"agent,omitempty"`
	} `json:"finding"`
}

// webhookScanCompletePayload is the JSON body sent for a scan-complete notification.
type webhookScanCompletePayload struct {
	Event     string                 `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	FlowID    string                 `json:"flow_id"`
	Summary   map[string]interface{} `json:"summary"`
}

// NotifyFinding sends a webhook notification for a new finding.
// It sends to all configs that subscribe to "critical_finding" or "high_finding"
// (depending on severity) or any config with no event filter.
func (w *WebhookNotifier) NotifyFinding(f *Finding) error {
	sev := strings.ToLower(strings.TrimSpace(f.Severity))
	var eventName string
	switch sev {
	case "critical":
		eventName = "critical_finding"
	case "high":
		eventName = "high_finding"
	default:
		eventName = "finding"
	}

	payload := webhookFindingPayload{
		Event:     eventName,
		Timestamp: time.Now().UTC(),
	}
	payload.Finding.Type = f.Type
	payload.Finding.URL = f.URL
	payload.Finding.Parameter = f.Parameter
	payload.Finding.Payload = f.Payload
	payload.Finding.Severity = f.Severity
	payload.Finding.Confidence = f.Confidence
	payload.Finding.Evidence = f.Evidence
	payload.Finding.Method = f.Method
	payload.Finding.Agent = f.Agent

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal finding payload: %w", err)
	}

	var firstErr error
	for _, cfg := range w.configs {
		if !w.shouldSend(cfg, eventName) {
			continue
		}
		if err := w.post(cfg, body); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// NotifyScanComplete sends a webhook notification when a scan finishes.
func (w *WebhookNotifier) NotifyScanComplete(flowID string, summary map[string]interface{}) error {
	payload := webhookScanCompletePayload{
		Event:     "scan_complete",
		Timestamp: time.Now().UTC(),
		FlowID:    flowID,
		Summary:   summary,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal scan_complete payload: %w", err)
	}

	var firstErr error
	for _, cfg := range w.configs {
		if !w.shouldSend(cfg, "scan_complete") {
			continue
		}
		if err := w.post(cfg, body); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// shouldSend returns true if the config is interested in the given event name.
func (w *WebhookNotifier) shouldSend(cfg WebhookConfig, eventName string) bool {
	if len(cfg.Events) == 0 {
		return true // no filter means all events
	}
	for _, e := range cfg.Events {
		if strings.EqualFold(e, eventName) {
			return true
		}
	}
	return false
}

// post sends a signed HTTP POST to the webhook URL.
func (w *WebhookNotifier) post(cfg WebhookConfig, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: create request to %s: %w", cfg.URL, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mirage-Webhook/1.0")

	// Add HMAC-SHA256 signature if a secret is configured.
	if cfg.Secret != "" {
		sig := computeHMACSHA256(body, cfg.Secret)
		req.Header.Set("X-Mirage-Signature", "sha256="+sig)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: POST to %s: %w", cfg.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: %s returned HTTP %d", cfg.URL, resp.StatusCode)
	}
	return nil
}

// computeHMACSHA256 returns the hex-encoded HMAC-SHA256 of payload using secret.
func computeHMACSHA256(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
