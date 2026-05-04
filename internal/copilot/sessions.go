package copilot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	claudeAPI   = "https://api.anthropic.com/v1/messages"
	claudeModel = "claude-sonnet-4-6"
	maxHistory  = 40 // messages kept per session
)

// Message is a single conversation turn.
type Message struct {
	Role    string `json:"role"`    // user|assistant
	Content string `json:"content"`
}

// Session holds the history for one chat session.
type Session struct {
	ID        string
	Messages  []Message
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store manages in-memory chat sessions.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewStore creates a session store.
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

// New creates a new session and returns it.
func (st *Store) New() *Session {
	s := &Session{
		ID:        uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	st.mu.Lock()
	st.sessions[s.ID] = s
	st.mu.Unlock()
	return s
}

// Get retrieves a session by ID.
func (st *Store) Get(id string) (*Session, bool) {
	st.mu.RLock()
	s, ok := st.sessions[id]
	st.mu.RUnlock()
	return s, ok
}

// Delete removes a session.
func (st *Store) Delete(id string) {
	st.mu.Lock()
	delete(st.sessions, id)
	st.mu.Unlock()
}

// Append adds messages to a session, trimming history if needed.
func (st *Store) Append(id string, msgs ...Message) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return false
	}
	s.Messages = append(s.Messages, msgs...)
	if len(s.Messages) > maxHistory {
		s.Messages = s.Messages[len(s.Messages)-maxHistory:]
	}
	s.UpdatedAt = time.Now()
	return true
}

// History returns a copy of the message history.
func (st *Store) History(id string) []Message {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s, ok := st.sessions[id]
	if !ok {
		return nil
	}
	out := make([]Message, len(s.Messages))
	copy(out, s.Messages)
	return out
}

// ── Streaming inference ───────────────────────────────────────────────────────

// StreamEvent is the SSE payload forwarded to the browser.
type StreamEvent struct {
	Type  string `json:"type"`            // start|delta|done|error
	Text  string `json:"text,omitempty"`
	Error string `json:"error,omitempty"`
}

// Chat sends the conversation to Claude and streams the response as SSE.
// platformContext is included as a non-cached system block.
func Chat(ctx context.Context, history []Message, platformContext string, w io.Writer, flush func()) (string, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		writeSSE(w, StreamEvent{Type: "error", Error: "ANTHROPIC_API_KEY not configured"}, flush)
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	systemBlocks := []map[string]interface{}{
		{
			"type": "text",
			"text": staticSystemPrompt(),
			"cache_control": map[string]string{"type": "ephemeral"},
		},
	}
	if platformContext != "" {
		systemBlocks = append(systemBlocks, map[string]interface{}{
			"type": "text",
			"text": platformContext,
		})
	}

	msgs := make([]map[string]interface{}, len(history))
	for i, m := range history {
		msgs[i] = map[string]interface{}{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{
		"model":      claudeModel,
		"max_tokens": 2048,
		"stream":     true,
		"system":     systemBlocks,
		"messages":   msgs,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, claudeAPI, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeSSE(w, StreamEvent{Type: "error", Error: err.Error()}, flush)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("Claude API HTTP %d: %s", resp.StatusCode, string(b))
		writeSSE(w, StreamEvent{Type: "error", Error: msg}, flush)
		return "", fmt.Errorf("%s", msg)
	}

	writeSSE(w, StreamEvent{Type: "start"}, flush)

	var assembled strings.Builder //nolint
	scanner := bufio.NewScanner(resp.Body)
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
		if json.Unmarshal([]byte(raw), &ev) != nil {
			continue
		}
		if ev.Type == "content_block_delta" && ev.Delta.Type == "text_delta" && ev.Delta.Text != "" {
			assembled.WriteString(ev.Delta.Text)
			writeSSE(w, StreamEvent{Type: "delta", Text: ev.Delta.Text}, flush)
		}
	}

	writeSSE(w, StreamEvent{Type: "done"}, flush)
	return assembled.String(), nil
}

func writeSSE(w io.Writer, ev StreamEvent, flush func()) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", b)
	if flush != nil {
		flush()
	}
}

func staticSystemPrompt() string {
	return `You are an expert penetration testing analyst and security engineer embedded inside Mirage, an autonomous AI-powered attack surface management platform. Your role is to help security teams understand vulnerabilities, assess risk, plan remediations, and interpret scan data.

Capabilities:
- Explain any vulnerability type (XSS, SQLi, SSRF, LFI, XXE, SSTI, IDOR, deserialization, etc.) clearly and accurately
- Provide concrete, prioritised remediation guidance with code examples where helpful
- Interpret CVSS scores, EPSS probabilities, and KEV status in business context
- Map findings to MITRE ATT&CK techniques and explain attack progression
- Identify relationships between findings that form exploit chains
- Draft findings descriptions suitable for pentest reports
- Suggest follow-up tests for any given vulnerability type

Response style:
- Be direct and precise — security professionals value density over padding
- Use Markdown for code, lists, and structured output
- Cite OWASP, CVE IDs, CWE numbers, and ATT&CK technique IDs where relevant
- When asked about specific findings, reference the data provided in context
- Never fabricate CVEs, finding details, or technical facts not in scope`
}
