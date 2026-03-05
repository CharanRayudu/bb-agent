package agent

import (
	"strings"
)

// ReflectionContext defines where a payload is reflected
type ReflectionContext string

const (
	ContextHTML      ReflectionContext = "html"
	ContextAttribute ReflectionContext = "attribute"
	ContextJS        ReflectionContext = "js"
	ContextJSON      ReflectionContext = "json"
	ContextCSS       ReflectionContext = "css"
	ContextUnknown   ReflectionContext = "unknown"
)

// Manipulator handles algorithmic payload breakout and mutation
type Manipulator struct{}

// NewManipulator creates a new breakout engine
func NewManipulator() *Manipulator {
	return &Manipulator{}
}

// DetectContext attempts to guess the reflection context from a sample response snippet
func (m *Manipulator) DetectContext(snippet string) ReflectionContext {
	low := strings.ToLower(snippet)

	if strings.Contains(low, "<script") {
		return ContextJS
	}
	if strings.Contains(low, "=\"") || strings.Contains(low, "='") {
		return ContextAttribute
	}
	if strings.Contains(low, "{\"") || strings.Contains(low, "[\"") {
		return ContextJSON
	}
	if strings.Contains(low, "style") || strings.Contains(low, "{") {
		return ContextCSS
	}
	if strings.Contains(low, "<") {
		return ContextHTML
	}

	return ContextUnknown
}

// WrapPayload prepends necessary breakout characters based on context
func (m *Manipulator) WrapPayload(payload string, context ReflectionContext) string {
	switch context {
	case ContextHTML:
		return "</span>" + payload // Try to break out of span or general tag
	case ContextAttribute:
		return "\"><" + payload + ">" // Break out of attribute and start new tag
	case ContextJS:
		return "'; " + payload + "; //" // Break out of JS string and comment out rest
	case ContextJSON:
		return "\"}, " + payload + ", {\"a\":\"" // Break out of JSON object
	case ContextCSS:
		return "}; " + payload + " { " // Break out of CSS rule
	default:
		return payload
	}
}

// GetEvasionWrappers returns common WAF evasion mutations
func (m *Manipulator) GetEvasionWrappers(payload string) []string {
	return []string{
		payload,
		strings.ReplaceAll(payload, " ", "/**/"), // SQL space bypass
		strings.ReplaceAll(payload, "<", "%3c"),  // URL encode
		strings.ToUpper(payload),                 // Case mixing
		"/*!" + payload + "*/",                   // MySQL version comment
	}
}
