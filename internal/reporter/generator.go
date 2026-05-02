package reporter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	claudeAPI   = "https://api.anthropic.com/v1/messages"
	claudeModel = "claude-sonnet-4-6"
)

// Generator streams AI-powered pentest reports via the Claude API.
type Generator struct {
	client *http.Client
	apiKey string
}

// NewGenerator creates a new report generator. API key read from ANTHROPIC_API_KEY.
func NewGenerator() *Generator {
	return &Generator{
		client: &http.Client{Timeout: 180 * time.Second},
		apiKey: os.Getenv("ANTHROPIC_API_KEY"),
	}
}

// Available returns true when an API key is configured.
func (g *Generator) Available() bool { return g.apiKey != "" }

// ReportRequest is the client-facing request shape.
type ReportRequest struct {
	FlowID             string `json:"flow_id"`
	Template           string `json:"template"` // executive|technical|compliance|full
	Format             string `json:"format"`   // markdown (default)
	IncludeThreatIntel bool   `json:"include_threat_intel"`
	IncludeMonitoring  bool   `json:"include_monitoring"`
}

// ReportData aggregates findings and metrics used to build the prompt.
type ReportData struct {
	Target    string
	ScanDate  string
	FlowName  string
	Findings  []FindingSummary
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
	// Threat intelligence enrichment
	TacticCount    int
	TechniqueCount int
	ChainCount     int
	// Continuous monitoring
	MonitorCount     int
	NewSinceBaseline int
}

// FindingSummary is a condensed finding used in the prompt.
type FindingSummary struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
}

// StreamEvent is the SSE payload sent to the browser.
type StreamEvent struct {
	Type  string `json:"type"`            // start|delta|done|error
	Text  string `json:"text,omitempty"`
	Error string `json:"error,omitempty"`
	Total int    `json:"total,omitempty"`
}

// Generate streams a report as SSE events written to w. flush is called after each event.
func (g *Generator) Generate(ctx context.Context, req ReportRequest, data ReportData, w io.Writer, flush func()) error {
	if g.apiKey == "" {
		writeSSE(w, StreamEvent{Type: "error", Error: "ANTHROPIC_API_KEY not configured on server"}, flush)
		return fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	payload := map[string]interface{}{
		"model":      claudeModel,
		"max_tokens": 8192,
		"stream":     true,
		"system": []map[string]interface{}{
			{
				"type": "text",
				"text": buildSystemPrompt(),
				"cache_control": map[string]string{"type": "ephemeral"},
			},
		},
		"messages": []map[string]interface{}{
			{"role": "user", "content": buildUserPrompt(req, data)},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, claudeAPI, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-api-key", g.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
	httpReq.Header.Set("content-type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		writeSSE(w, StreamEvent{Type: "error", Error: err.Error()}, flush)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("Claude API returned HTTP %d: %s", resp.StatusCode, string(b))
		writeSSE(w, StreamEvent{Type: "error", Error: msg}, flush)
		return fmt.Errorf("%s", msg)
	}

	writeSSE(w, StreamEvent{Type: "start"}, flush)

	total := 0
	scanner := bufio.NewScanner(resp.Body)
	// Increase scanner buffer for large SSE lines
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 6 || line[:6] != "data: " {
			continue
		}
		raw := line[6:]
		if raw == "[DONE]" {
			break
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue
		}
		if ev.Type == "content_block_delta" && ev.Delta.Type == "text_delta" && ev.Delta.Text != "" {
			total += len(ev.Delta.Text)
			writeSSE(w, StreamEvent{Type: "delta", Text: ev.Delta.Text}, flush)
		}
	}

	writeSSE(w, StreamEvent{Type: "done", Total: total}, flush)
	return nil
}

func writeSSE(w io.Writer, ev StreamEvent, flush func()) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", b)
	if flush != nil {
		flush()
	}
}
