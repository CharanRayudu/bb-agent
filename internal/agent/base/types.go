package base

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/queue"
)

// Finding represents a confirmed or suspected vulnerability.
type Finding struct {
	Type       string                 `json:"type"`       // XSS, SQLi, SSRF, etc.
	URL        string                 `json:"url"`        // Target URL
	Parameter  string                 `json:"parameter"`  // Vulnerable parameter
	Payload    string                 `json:"payload"`    // Triggering payload
	Severity   string                 `json:"severity"`   // critical, high, medium, low, info
	Confidence float64                `json:"confidence"` // 0.0 - 1.0
	Evidence   map[string]interface{} `json:"evidence"`   // Supporting evidence
	Method     string                 `json:"method"`     // GET, POST, etc.
	Agent      string                 `json:"agent"`      // Which agent found this
	SubTaskID  string                 `json:"subtask_id,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// Specialist is the interface that all vulnerability-specific agents must implement.
type Specialist interface {
	Name() string
	ID() string
	ProcessItem(ctx context.Context, item *queue.Item) ([]*Finding, error)
	SystemPrompt() string
}

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

var ConversationalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(Try|Navigate|Inject|Use|Attempt|Test for|Set|Access|Exploit|Check|Verify|Submit)\s`),
	regexp.MustCompile(`\(e\.g\.,`),
	regexp.MustCompile(`(?i)to (verify|exfiltrate|access|bypass|leak|confirm|test|execute)`),
	regexp.MustCompile(`(?i)(such as|Alternatively|progress to|Start with|for instance)`),
	regexp.MustCompile(`(?i)(or use|or try|or attempt)`),
	regexp.MustCompile(`(?i)payload (could|should|must) be`),
	regexp.MustCompile(`(?i)strategy:`),
	regexp.MustCompile(`(?i)logic:`),
}

// ValidateFindingSurface checks the required target metadata for a finding.
// Use this for unverified leads that should still point at a valid URL.
func ValidateFindingSurface(f *Finding) error {
	if f == nil {
		return fmt.Errorf("finding is nil")
	}
	if f.Type == "" {
		return fmt.Errorf("missing vulnerability type")
	}
	if f.URL == "" {
		return fmt.Errorf("missing target URL")
	}
	if !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
		return fmt.Errorf("invalid URL scheme: %s", f.URL)
	}
	if err := validateFindingURL(f.URL); err != nil {
		return err
	}
	return nil
}

// ValidateFinding checks if a finding is valid before emitting.
func ValidateFinding(f *Finding) error {
	if err := ValidateFindingSurface(f); err != nil {
		return err
	}

	// Check for conversational/hallucinated payloads
	if f.Payload != "" {
		for _, pattern := range ConversationalPatterns {
			if pattern.MatchString(f.Payload) {
				return fmt.Errorf("conversational payload detected: %.50s...", f.Payload)
			}
		}
	}
	return nil
}

func validateFindingURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid finding URL: %w", err)
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("finding URL missing host: %s", raw)
	}

	lowerRaw := strings.ToLower(raw)
	suspiciousFragments := []string{
		"//dtd",
		"http://w3c",
		"https://w3c",
	}
	for _, fragment := range suspiciousFragments {
		if strings.Contains(lowerRaw, fragment) {
			return fmt.Errorf("suspicious finding URL artifact: %s", raw)
		}
	}

	if strings.ContainsAny(host, `<> "'`) {
		return fmt.Errorf("finding URL host contains invalid characters: %s", raw)
	}

	return nil
}
