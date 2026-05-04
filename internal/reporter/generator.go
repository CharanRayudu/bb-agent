package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// Generator streams AI-powered pentest reports via the configured Mirage LLM provider.
type Generator struct {
	provider    llm.Provider
	model       string
	temperature float64
}

// NewGenerator creates a new report generator using the shared Codex/OpenAI provider.
func NewGenerator(provider llm.Provider, model string, temperature float64) *Generator {
	return &Generator{
		provider:    provider,
		model:       model,
		temperature: temperature,
	}
}

// Available returns true when a shared LLM provider is configured.
func (g *Generator) Available() bool { return g != nil && g.provider != nil }

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
	Target   string
	ScanDate string
	FlowName string
	Findings []FindingSummary
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
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
	Type  string `json:"type"` // start|delta|done|error
	Text  string `json:"text,omitempty"`
	Error string `json:"error,omitempty"`
	Total int    `json:"total,omitempty"`
}

// Generate streams a report as SSE events written to w. flush is called after each event.
func (g *Generator) Generate(ctx context.Context, req ReportRequest, data ReportData, w io.Writer, flush func()) error {
	if g == nil || g.provider == nil {
		writeSSE(w, StreamEvent{Type: "error", Error: "Codex/OpenAI LLM authentication is not configured"}, flush)
		return fmt.Errorf("llm provider not configured")
	}

	writeSSE(w, StreamEvent{Type: "start"}, flush)

	resp, err := g.provider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: buildSystemPrompt()},
			{Role: "user", Content: buildUserPrompt(req, data)},
		},
		Model:       g.model,
		Temperature: g.temperature,
	})
	if err != nil {
		writeSSE(w, StreamEvent{Type: "error", Error: err.Error()}, flush)
		return err
	}

	text := strings.TrimSpace(resp.Content)
	if text != "" {
		writeSSE(w, StreamEvent{Type: "delta", Text: text}, flush)
	}
	writeSSE(w, StreamEvent{Type: "done", Total: len(text)}, flush)
	return nil
}

func writeSSE(w io.Writer, ev StreamEvent, flush func()) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", b)
	if flush != nil {
		flush()
	}
}
