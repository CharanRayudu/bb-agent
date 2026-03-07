// Package schema provides structured validation for LLM outputs.
//
// It extracts JSON from noisy LLM responses (code fences, escaped strings,
// embedded commentary), validates against typed Go schemas, and provides
// automatic retry-with-correction logic for malformed outputs.
package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// JSON Extraction -- Multi-strategy parser for LLM output
// ---------------------------------------------------------------------------

var (
	// Match JSON inside markdown code fences: ```json ... ``` or ``` ... ```
	codeFenceRe = regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(\\[.*?\\]|\\{.*?\\})\\s*```")
	// Match a top-level JSON array or object
	rawJSONRe = regexp.MustCompile(`(?s)(\[[\s\S]*\]|\{[\s\S]*\})`)
)

// ExtractJSON attempts to extract a JSON string from noisy LLM output.
// It tries multiple strategies in priority order:
//  1. JSON inside markdown code fences
//  2. Escaped JSON string (double-encoded)
//  3. Raw JSON array or object in text
//
// Returns the extracted JSON string, or empty string if nothing found.
func ExtractJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Strategy 1: Code fence extraction (highest priority -- most intentional)
	if matches := codeFenceRe.FindStringSubmatch(raw); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Strategy 2: If the entire string is a JSON-escaped string, unescape it
	if strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
		var unescaped string
		if err := json.Unmarshal([]byte(raw), &unescaped); err == nil {
			unescaped = strings.TrimSpace(unescaped)
			if isJSONLike(unescaped) {
				return unescaped
			}
		}
	}

	// Strategy 3: Find the largest JSON structure in the text
	if isJSONLike(raw) {
		return raw
	}

	// Look for JSON embedded in commentary text
	if match := rawJSONRe.FindString(raw); match != "" {
		// Validate it's actual JSON, not just brackets in prose
		match = strings.TrimSpace(match)
		if json.Valid([]byte(match)) {
			return match
		}
	}

	return ""
}

// isJSONLike checks if a string looks like it starts with JSON structure
func isJSONLike(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) ||
		(strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"))
}

// ---------------------------------------------------------------------------
// Typed Validation
// ---------------------------------------------------------------------------

// Validatable interface for types that can self-validate after unmarshaling.
type Validatable interface {
	Validate() error
}

// Parse extracts JSON from raw LLM output and unmarshals it into the target type.
// If the target implements Validatable, it also runs validation.
// Returns a descriptive error suitable for sending back to the LLM as a correction prompt.
func Parse[T any](raw string) (T, error) {
	var zero T

	jsonStr := ExtractJSON(raw)
	if jsonStr == "" {
		return zero, fmt.Errorf(
			"no valid JSON found in your response. Return ONLY a JSON %s with no surrounding text or markdown",
			jsonTypeName[T](),
		)
	}

	var result T
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return zero, fmt.Errorf(
			"JSON parsing failed: %s. Fix the JSON syntax and return ONLY valid JSON",
			err.Error(),
		)
	}

	// Run semantic validation if the type supports it
	if v, ok := any(&result).(Validatable); ok {
		if err := v.Validate(); err != nil {
			return zero, fmt.Errorf(
				"schema validation failed: %s. Fix the issue and return corrected JSON",
				err.Error(),
			)
		}
	}

	return result, nil
}

// jsonTypeName returns a human-readable name for error messages
func jsonTypeName[T any]() string {
	var zero T
	switch any(zero).(type) {
	case []any:
		return "array"
	default:
		// Check if it's a slice type
		name := fmt.Sprintf("%T", zero)
		if strings.HasPrefix(name, "[]") {
			return "array"
		}
		return "object"
	}
}

// ---------------------------------------------------------------------------
// Correction Prompt Builder
// ---------------------------------------------------------------------------

// CorrectionPrompt builds a system message to send back to the LLM
// when schema validation fails, asking it to fix its output.
func CorrectionPrompt(validationErr error, originalResponse string) string {
	return fmt.Sprintf(
		"Your previous response failed validation:\n\n**Error**: %s\n\n"+
			"Please fix the issue and respond with ONLY the corrected JSON. "+
			"No explanation, no markdown code fences, no commentary -- just the raw JSON.",
		validationErr.Error(),
	)
}
