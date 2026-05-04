package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

const maxHistory = 40 // messages kept per session

// Message is a single conversation turn.
type Message struct {
	Role    string `json:"role"` // user|assistant
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

// StreamEvent is the SSE payload forwarded to the browser.
type StreamEvent struct {
	Type  string `json:"type"` // start|delta|done|error
	Text  string `json:"text,omitempty"`
	Error string `json:"error,omitempty"`
}

// Chat sends the conversation to the configured Mirage LLM provider and streams the response as SSE.
func Chat(ctx context.Context, provider llm.Provider, model string, temperature float64, history []Message, platformContext string, w io.Writer, flush func()) (string, error) {
	if provider == nil {
		writeSSE(w, StreamEvent{Type: "error", Error: "Codex/OpenAI LLM authentication is not configured"}, flush)
		return "", fmt.Errorf("llm provider not configured")
	}

	systemPrompt := staticSystemPrompt()
	if platformContext != "" {
		systemPrompt += "\n\n" + platformContext
	}

	messages := make([]models.ChatMessage, 0, len(history)+1)
	messages = append(messages, models.ChatMessage{Role: "system", Content: systemPrompt})
	for _, m := range history {
		role := m.Role
		if role != "assistant" && role != "user" {
			role = "user"
		}
		messages = append(messages, models.ChatMessage{Role: role, Content: m.Content})
	}

	writeSSE(w, StreamEvent{Type: "start"}, flush)

	resp, err := provider.Complete(ctx, llm.CompletionRequest{
		Messages:    messages,
		Model:       model,
		Temperature: temperature,
	})
	if err != nil {
		writeSSE(w, StreamEvent{Type: "error", Error: err.Error()}, flush)
		return "", err
	}

	reply := strings.TrimSpace(resp.Content)
	if reply != "" {
		writeSSE(w, StreamEvent{Type: "delta", Text: reply}, flush)
	}
	writeSSE(w, StreamEvent{Type: "done"}, flush)
	return reply, nil
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
- Be direct and precise; security professionals value density over padding
- Use Markdown for code, lists, and structured output
- Cite OWASP, CVE IDs, CWE numbers, and ATT&CK technique IDs where relevant
- When asked about specific findings, reference the data provided in context
- Never fabricate CVEs, finding details, or technical facts not in scope`
}
