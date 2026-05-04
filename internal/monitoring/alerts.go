package monitoring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AlertEvent is sent to alert channels when a notable delta is detected.
type AlertEvent struct {
	MonitorID   string    `json:"monitor_id"`
	MonitorName string    `json:"monitor_name"`
	Target      string    `json:"target"`
	Delta       Delta     `json:"delta"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"` // highest severity in delta
}

// Dispatcher sends alert events to configured channels.
type Dispatcher struct {
	store  *Store
	client *http.Client
}

// NewDispatcher creates a new alert dispatcher.
func NewDispatcher(store *Store) *Dispatcher {
	return &Dispatcher{
		store:  store,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Dispatch sends an alert to all channels registered on the monitor, subject to
// the channel's min_severity filter.
func (d *Dispatcher) Dispatch(ctx context.Context, event AlertEvent, channelIDs []string) []error {
	var errs []error
	for _, id := range channelIDs {
		ch, ok := d.store.GetChannel(id)
		if !ok || !ch.Enabled {
			continue
		}
		if !severityMeetsThreshold(event.Severity, ch.MinSeverity) {
			continue
		}
		if err := d.send(ctx, ch, event); err != nil {
			errs = append(errs, fmt.Errorf("channel %s (%s): %w", ch.Name, ch.Type, err))
		}
	}
	return errs
}

// SendTest sends a test alert to a specific channel to verify connectivity.
func (d *Dispatcher) SendTest(ctx context.Context, channelID string) error {
	ch, ok := d.store.GetChannel(channelID)
	if !ok {
		return fmt.Errorf("channel %s not found", channelID)
	}
	event := AlertEvent{
		MonitorName: "Test Monitor",
		Target:      "https://example.com",
		Timestamp:   time.Now(),
		Severity:    "info",
		Delta: Delta{
			Summary:     "This is a test alert from Mirage",
			NewFindings: []FindingSummary{{Type: "Test", Title: "Test Finding", Severity: "info"}},
		},
	}
	return d.send(ctx, ch, event)
}

func (d *Dispatcher) send(ctx context.Context, ch *AlertChannel, event AlertEvent) error {
	switch ch.Type {
	case ChannelSlack:
		return d.sendSlack(ctx, ch, event)
	case ChannelPagerDuty:
		return d.sendPagerDuty(ctx, ch, event)
	case ChannelTeams:
		return d.sendTeams(ctx, ch, event)
	case ChannelWebhook:
		return d.sendWebhook(ctx, ch, event)
	default:
		return fmt.Errorf("unknown channel type: %s", ch.Type)
	}
}

// ── Slack ─────────────────────────────────────────────────────────────────────

func (d *Dispatcher) sendSlack(ctx context.Context, ch *AlertChannel, e AlertEvent) error {
	color := slackColor(e.Severity)
	text := fmt.Sprintf("*%s* — %s", e.MonitorName, e.Target)

	fields := []map[string]interface{}{
		{"title": "Summary", "value": e.Delta.Summary, "short": false},
		{"title": "Severity", "value": strings.ToUpper(e.Severity), "short": true},
	}
	if len(e.Delta.NewFindings) > 0 {
		names := make([]string, 0, 5)
		for _, f := range e.Delta.NewFindings {
			if len(names) >= 5 {
				names = append(names, fmt.Sprintf("…and %d more", len(e.Delta.NewFindings)-5))
				break
			}
			names = append(names, fmt.Sprintf("• [%s] %s", strings.ToUpper(f.Severity), f.Title))
		}
		fields = append(fields, map[string]interface{}{
			"title": "New Findings",
			"value": strings.Join(names, "\n"),
			"short": false,
		})
	}
	if len(e.Delta.ResolvedFindings) > 0 {
		fields = append(fields, map[string]interface{}{
			"title": "Resolved",
			"value": fmt.Sprintf("%d finding(s) resolved since baseline", len(e.Delta.ResolvedFindings)),
			"short": true,
		})
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":       color,
				"title":       "Mirage: Attack Surface Change Detected",
				"text":        text,
				"fields":      fields,
				"footer":      "Mirage Autonomous Pentest",
				"footer_icon": "https://mirage.sec/icon.png",
				"ts":          e.Timestamp.Unix(),
			},
		},
	}

	return d.postJSON(ctx, ch.URL, payload)
}

func slackColor(severity string) string {
	switch severity {
	case "critical":
		return "#ff4757"
	case "high":
		return "#ff7f50"
	case "medium":
		return "#eccc68"
	case "low":
		return "#2ed573"
	default:
		return "#888888"
	}
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

func (d *Dispatcher) sendPagerDuty(ctx context.Context, ch *AlertChannel, e AlertEvent) error {
	routingKey := ch.Config["routing_key"]
	if routingKey == "" {
		routingKey = ch.URL // treat URL as routing key for legacy configs
	}

	pdSeverity := "info"
	switch e.Severity {
	case "critical":
		pdSeverity = "critical"
	case "high":
		pdSeverity = "error"
	case "medium":
		pdSeverity = "warning"
	case "low":
		pdSeverity = "info"
	}

	dedupKey := fmt.Sprintf("mirage-%s-%s", e.MonitorID, e.Timestamp.Format("2006-01-02"))

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("Mirage: %s — %s", e.MonitorName, e.Delta.Summary),
			"timestamp": e.Timestamp.Format(time.RFC3339),
			"severity":  pdSeverity,
			"source":    e.Target,
			"custom_details": map[string]interface{}{
				"new_findings": len(e.Delta.NewFindings),
				"resolved":     len(e.Delta.ResolvedFindings),
				"regressions":  len(e.Delta.Regressions),
				"risk_delta":   e.Delta.RiskDelta,
				"monitor_id":   e.MonitorID,
			},
		},
		"links": []map[string]string{
			{"href": "https://mirage.sec/monitors/" + e.MonitorID, "text": "View in Mirage"},
		},
	}

	return d.postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

func (d *Dispatcher) sendTeams(ctx context.Context, ch *AlertChannel, e AlertEvent) error {
	themeColor := slackColor(e.Severity)[1:] // strip '#'

	facts := []map[string]string{
		{"name": "Target", "value": e.Target},
		{"name": "Summary", "value": e.Delta.Summary},
		{"name": "Severity", "value": strings.ToUpper(e.Severity)},
		{"name": "New Findings", "value": fmt.Sprintf("%d", len(e.Delta.NewFindings))},
		{"name": "Resolved", "value": fmt.Sprintf("%d", len(e.Delta.ResolvedFindings))},
	}

	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor,
		"summary":    "Mirage Attack Surface Change",
		"sections": []map[string]interface{}{
			{
				"activityTitle":    fmt.Sprintf("Attack Surface Change: %s", e.MonitorName),
				"activitySubtitle": e.Target,
				"activityImage":    "https://mirage.sec/icon.png",
				"facts":            facts,
				"markdown":         true,
			},
		},
		"potentialAction": []map[string]interface{}{
			{
				"@type": "OpenUri",
				"name":  "View in Mirage",
				"targets": []map[string]string{
					{"os": "default", "uri": "https://mirage.sec/monitors/" + e.MonitorID},
				},
			},
		},
	}

	return d.postJSON(ctx, ch.URL, payload)
}

// ── Generic Webhook ───────────────────────────────────────────────────────────

func (d *Dispatcher) sendWebhook(ctx context.Context, ch *AlertChannel, e AlertEvent) error {
	return d.postJSON(ctx, ch.URL, e)
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

func (d *Dispatcher) postJSON(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mirage-Monitoring/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Severity helpers ──────────────────────────────────────────────────────────

var severityRanks = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

func severityMeetsThreshold(actual, threshold string) bool {
	return severityRanks[actual] >= severityRanks[threshold]
}

// HighestSeverity returns the highest severity among a set of findings.
func HighestSeverity(findings []FindingSummary) string {
	best := "info"
	for _, f := range findings {
		if severityRanks[f.Severity] > severityRanks[best] {
			best = f.Severity
		}
	}
	return best
}
