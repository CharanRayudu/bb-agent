package agent

import (
	"strings"
)

// WAFStrategy defines an encoding or evasion technique
type WAFStrategy struct {
	Name        string
	Description string
	Encodings   []string // e.g., "url", "double_url", "html_entity", "unicode"
}

// WAFStrategist tracks block history and suggests evasion strategies
type WAFStrategist struct {
	// History of blocks per tool/target
	blockCount map[string]int
}

// NewWAFStrategist creates a new strategist
func NewWAFStrategist() *WAFStrategist {
	return &WAFStrategist{
		blockCount: make(map[string]int),
	}
}

// SuggestedEncoding returns the best encoding technique based on block history
func (s *WAFStrategist) SuggestedEncoding(toolName string, output string) string {
	s.blockCount[toolName]++
	count := s.blockCount[toolName]

	// Analyze output for specific WAF signatures
	lower := strings.ToLower(output)

	if strings.Contains(lower, "cloudflare") {
		return "cf_bypass_header"
	}
	if strings.Contains(lower, "akamai") {
		return "akamai_edge_obfuscation"
	}
	if strings.Contains(lower, "mod_security") {
		return "null_byte_injection"
	}

	// Default strategies based on block depth
	switch count % 5 {
	case 1:
		return "url_encode"
	case 2:
		return "double_url_encode"
	case 3:
		return "html_entity_encode"
	case 4:
		return "unicode_escape"
	case 0:
		return "base64_wrap"
	}

	return "standard"
}

// GetStrategyPayload wraps a payload with the suggested encoding
func (s *WAFStrategist) GetStrategyPayload(payload, strategy string) string {
	switch strategy {
	case "url_encode":
		return strings.ReplaceAll(payload, "'", "%27") // simplified
	case "double_url_encode":
		return strings.ReplaceAll(payload, "'", "%2527")
	case "unicode_escape":
		return "\\u0027" // simplified example
	default:
		return payload
	}
}

// Reset clears the block history for a tool
func (s *WAFStrategist) Reset(toolName string) {
	delete(s.blockCount, toolName)
}
