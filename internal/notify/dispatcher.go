package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// EventPayload is the body delivered to channels.
type EventPayload struct {
	Event     string                 `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Dispatcher delivers events to configured channels.
type Dispatcher struct {
	store *Store
}

func NewDispatcher(store *Store) *Dispatcher {
	return &Dispatcher{store: store}
}

// Dispatch fires goroutines to deliver the event to every subscribed, enabled channel.
func (d *Dispatcher) Dispatch(event string, data map[string]interface{}) {
	channels := d.store.ForEvent(event)
	if len(channels) == 0 {
		return
	}
	p := EventPayload{
		Event:     event,
		Timestamp: time.Now(),
		Data:      data,
	}
	for _, ch := range channels {
		go func(ch *Channel) {
			if err := d.send(ch, p); err != nil {
				log.Printf("[NOTIFY] %s → %s (%s): %v", event, ch.Name, ch.Type, err)
			}
		}(ch)
	}
}

// Test sends a test payload to the channel and records the timestamp on success.
func (d *Dispatcher) Test(id string) error {
	ch, ok := d.store.Get(id)
	if !ok {
		return fmt.Errorf("channel not found")
	}
	p := EventPayload{
		Event:     "test",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"message": "Test notification from Mirage."},
	}
	if err := d.send(ch, p); err != nil {
		return err
	}
	d.store.MarkTested(id)
	return nil
}

func (d *Dispatcher) send(ch *Channel, p EventPayload) error {
	switch ch.Type {
	case ChannelSlack:
		return d.sendSlack(ch, p)
	case ChannelWebhook:
		return d.sendWebhook(ch, p)
	case ChannelEmail:
		return d.sendEmail(ch, p)
	default:
		return fmt.Errorf("unknown channel type: %s", ch.Type)
	}
}

func (d *Dispatcher) sendSlack(ch *Channel, p EventPayload) error {
	if ch.Config.WebhookURL == "" {
		return fmt.Errorf("slack: webhook_url not configured")
	}
	emoji, color := slackStyle(p.Event)
	text := fmt.Sprintf("%s *[%s]* — %s", emoji, strings.ToUpper(p.Event), slackSummary(p.Data))
	body := map[string]interface{}{
		"text": text,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"fields": slackFields(p.Data),
				"footer": "Mirage · Autonomous Pentest",
				"ts":     p.Timestamp.Unix(),
			},
		},
	}
	return postJSON(ch.Config.WebhookURL, nil, body)
}

func (d *Dispatcher) sendWebhook(ch *Channel, p EventPayload) error {
	if ch.Config.WebhookURL == "" {
		return fmt.Errorf("webhook: url not configured")
	}
	return postJSON(ch.Config.WebhookURL, ch.Config.Headers, p)
}

func (d *Dispatcher) sendEmail(ch *Channel, p EventPayload) error {
	if ch.Config.SMTPHost == "" || len(ch.Config.To) == 0 {
		return fmt.Errorf("email: smtp_host and to are required")
	}
	port := ch.Config.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", ch.Config.SMTPHost, port)

	var auth smtp.Auth
	if ch.Config.Username != "" {
		auth = smtp.PlainAuth("", ch.Config.Username, ch.Config.Password, ch.Config.SMTPHost)
	}

	subject := fmt.Sprintf("[Mirage] %s", strings.ReplaceAll(p.Event, "_", " "))
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		ch.Config.From,
		strings.Join(ch.Config.To, ", "),
		subject,
		buildEmailBody(p),
	)
	return smtp.SendMail(addr, auth, ch.Config.From, ch.Config.To, []byte(msg))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func postJSON(url string, headers map[string]string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("remote returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func slackStyle(event string) (emoji, color string) {
	switch event {
	case "critical_finding":
		return "🚨", "#ff4444"
	case "high_finding":
		return "⚠️", "#ff8800"
	case "sla_breach":
		return "⏰", "#ff6600"
	case "scan_complete":
		return "✅", "#00cc44"
	case "schedule_fired":
		return "🔁", "#22d3ee"
	case "monitor_alert":
		return "📡", "#a78bfa"
	default:
		return "ℹ️", "#666666"
	}
}

func slackSummary(data map[string]interface{}) string {
	for _, k := range []string{"message", "title", "target", "name"} {
		if v, ok := data[k].(string); ok && v != "" {
			return v
		}
	}
	return "Event triggered"
}

func slackFields(data map[string]interface{}) []map[string]interface{} {
	var fields []map[string]interface{}
	for k, v := range data {
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": fmt.Sprintf("%v", v),
			"short": true,
		})
		if len(fields) >= 8 {
			break
		}
	}
	return fields
}

func buildEmailBody(p EventPayload) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Event:  %s\n", p.Event))
	sb.WriteString(fmt.Sprintf("Time:   %s\n\n", p.Timestamp.Format(time.RFC1123)))
	for k, v := range p.Data {
		sb.WriteString(fmt.Sprintf("  %-18s %v\n", k+":", v))
	}
	sb.WriteString("\n— Mirage Autonomous Security Platform\n")
	return sb.String()
}
