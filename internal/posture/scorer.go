package posture

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Snapshot is a point-in-time posture score with component breakdown.
type Snapshot struct {
	Score              float64            `json:"score"`            // 0-100
	Grade              string             `json:"grade"`            // A-F
	Components         ComponentScores    `json:"components"`
	FindingCounts      map[string]int     `json:"finding_counts"`
	OWASPCoverage      []OWASPCategory    `json:"owasp_coverage"`
	UrgentActions      []Action           `json:"urgent_actions"`
	Timestamp          time.Time          `json:"timestamp"`
}

// ComponentScores are the weighted inputs to the composite score.
type ComponentScores struct {
	CriticalExposure    float64 `json:"critical_exposure"`    // 0-100
	RemediationProgress float64 `json:"remediation_progress"` // 0-100
	SLAHealth           float64 `json:"sla_health"`           // 0-100
	MonitoringCoverage  float64 `json:"monitoring_coverage"`  // 0-100
	AttackSurface       float64 `json:"attack_surface"`       // 0-100
}

// weights must sum to 1.0
const (
	wExposure     = 0.35
	wRemediation  = 0.25
	wSLA          = 0.20
	wMonitoring   = 0.10
	wSurface      = 0.10
)

// OWASPCategory shows coverage for one OWASP Top 10 2021 item.
type OWASPCategory struct {
	ID       string `json:"id"`       // A01:2021
	Name     string `json:"name"`
	Exposed  bool   `json:"exposed"`  // findings found in this category
	Severity string `json:"severity"` // highest severity among matching findings
}

// Action is a prioritised recommendation.
type Action struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // critical|high|medium|low
}

// HistoryStore keeps up to 90 snapshots (rolling).
type HistoryStore struct {
	mu        sync.RWMutex
	snapshots []Snapshot
	max       int
}

// NewHistoryStore creates a history store.
func NewHistoryStore() *HistoryStore {
	return &HistoryStore{max: 90}
}

// Push adds a snapshot, evicting the oldest if full.
func (h *HistoryStore) Push(s Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snapshots = append(h.snapshots, s)
	if len(h.snapshots) > h.max {
		h.snapshots = h.snapshots[len(h.snapshots)-h.max:]
	}
}

// All returns a copy of all snapshots.
func (h *HistoryStore) All() []Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Snapshot, len(h.snapshots))
	copy(out, h.snapshots)
	return out
}

// ── Score computation ─────────────────────────────────────────────────────────

// Input is a summary of platform state used to compute the posture score.
type Input struct {
	FindingCounts    map[string]int // severity → count
	FindingTypes     []string       // unique finding type strings
	RemItems         int            // total remediation items tracked
	RemFixed         int            // fixed/verified
	SLABreached      int            // items with SLA breach
	SLACompliant     int            // items within SLA
	MonitorCount     int            // active monitors
	UniqueTargets    int            // total unique targets scanned
	OpenCritical     int            // open critical findings
	OpenHigh         int            // open high findings
}

// Compute returns a fully populated Snapshot.
func Compute(in Input) Snapshot {
	comp := ComponentScores{
		CriticalExposure:    criticalExposureScore(in),
		RemediationProgress: remediationScore(in),
		SLAHealth:           slaScore(in),
		MonitoringCoverage:  monitoringScore(in),
		AttackSurface:       attackSurfaceScore(in),
	}

	score := comp.CriticalExposure*wExposure +
		comp.RemediationProgress*wRemediation +
		comp.SLAHealth*wSLA +
		comp.MonitoringCoverage*wMonitoring +
		comp.AttackSurface*wSurface

	score = math.Round(score*10) / 10

	return Snapshot{
		Score:         score,
		Grade:         grade(score),
		Components:    comp,
		FindingCounts: in.FindingCounts,
		OWASPCoverage: buildOWASP(in.FindingTypes, in.FindingCounts),
		UrgentActions: buildActions(in),
		Timestamp:     time.Now(),
	}
}

func criticalExposureScore(in Input) float64 {
	// Start at 100, deduct for open critical/high findings
	s := 100.0
	s -= float64(in.OpenCritical) * 15
	s -= float64(in.OpenHigh) * 5
	return math.Max(0, math.Min(100, s))
}

func remediationScore(in Input) float64 {
	total := in.FindingCounts["critical"] + in.FindingCounts["high"] + in.FindingCounts["medium"]
	if total == 0 {
		return 90
	}
	if in.RemItems == 0 {
		return 10
	}
	pct := float64(in.RemFixed) / float64(in.RemItems) * 100
	coverage := float64(in.RemItems) / float64(total) * 100
	return math.Min(100, pct*0.6+coverage*0.4)
}

func slaScore(in Input) float64 {
	total := in.SLABreached + in.SLACompliant
	if total == 0 {
		return 80 // no items → assume moderate
	}
	return math.Min(100, float64(in.SLACompliant)/float64(total)*100)
}

func monitoringScore(in Input) float64 {
	if in.UniqueTargets == 0 {
		return 50
	}
	if in.MonitorCount == 0 {
		return 20
	}
	pct := float64(in.MonitorCount) / float64(in.UniqueTargets) * 100
	return math.Min(100, pct)
}

func attackSurfaceScore(in Input) float64 {
	// Score based on total finding count relative to a "low-risk" baseline
	total := 0
	for _, c := range in.FindingCounts {
		total += c
	}
	if total == 0 {
		return 85
	}
	// Each finding reduces the score; critical findings reduce more
	penalty := float64(in.FindingCounts["critical"])*8 +
		float64(in.FindingCounts["high"])*3 +
		float64(in.FindingCounts["medium"])*1
	return math.Max(0, math.Min(100, 100-penalty))
}

func grade(score float64) string {
	switch {
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────

var owaspCategories = []struct {
	ID       string
	Name     string
	Keywords []string
}{
	{"A01:2021", "Broken Access Control", []string{"IDOR", "Path Traversal", "LFI", "Auth Bypass", "Directory Listing"}},
	{"A02:2021", "Cryptographic Failures", []string{"Weak TLS", "Insecure Cookie", "JWT", "HTTP without HTTPS"}},
	{"A03:2021", "Injection", []string{"SQL", "SQLi", "Command Injection", "CMDi", "SSTI", "XSS", "XXE", "LDAP"}},
	{"A04:2021", "Insecure Design", []string{"SSRF", "Open Redirect", "Business Logic"}},
	{"A05:2021", "Security Misconfiguration", []string{"Container", "Misconfiguration", "CORS", "Security Header", "Default Credential"}},
	{"A06:2021", "Vulnerable Components", []string{"SCA", "CVE", "Dependency", "Log4", "Supply Chain"}},
	{"A07:2021", "Auth & Session Failures", []string{"Authentication", "Session Fixation", "OAuth", "SAML", "Brute Force"}},
	{"A08:2021", "Software Integrity Failures", []string{"Deserialization", "Integrity", "CICD", "Pipeline"}},
	{"A09:2021", "Logging & Monitoring Gaps", []string{"Secret", "Sensitive Data", "Information Disclosure"}},
	{"A10:2021", "SSRF", []string{"SSRF", "Server-Side Request"}},
}

func buildOWASP(findingTypes []string, counts map[string]int) []OWASPCategory {
	out := make([]OWASPCategory, 0, len(owaspCategories))
	allTypes := strings.Join(findingTypes, " ")

	for _, cat := range owaspCategories {
		exposed := false
		for _, kw := range cat.Keywords {
			if strings.Contains(strings.ToUpper(allTypes), strings.ToUpper(kw)) {
				exposed = true
				break
			}
		}
		sev := "info"
		if exposed {
			sev = severityForOWASP(cat.Keywords, findingTypes, counts)
		}
		out = append(out, OWASPCategory{
			ID:       cat.ID,
			Name:     cat.Name,
			Exposed:  exposed,
			Severity: sev,
		})
	}
	return out
}

func severityForOWASP(keywords, findingTypes []string, counts map[string]int) string {
	for _, ft := range findingTypes {
		for _, kw := range keywords {
			if strings.Contains(strings.ToUpper(ft), strings.ToUpper(kw)) {
				if counts["critical"] > 0 {
					return "critical"
				}
				if counts["high"] > 0 {
					return "high"
				}
				if counts["medium"] > 0 {
					return "medium"
				}
				return "low"
			}
		}
	}
	return "info"
}

// ── Urgent actions ────────────────────────────────────────────────────────────

func buildActions(in Input) []Action {
	var actions []Action

	if in.OpenCritical > 0 {
		actions = append(actions, Action{
			Priority: 1, Severity: "critical",
			Title:       "Address critical findings immediately",
			Description: pluralf("%d critical finding", "%d critical findings", in.OpenCritical) + " require immediate remediation (SLA: 24 hours).",
		})
	}
	if in.OpenHigh > 0 {
		actions = append(actions, Action{
			Priority: 2, Severity: "high",
			Title:       "Remediate high-severity findings",
			Description: pluralf("%d high-severity finding", "%d high-severity findings", in.OpenHigh) + " must be fixed within 7 days.",
		})
	}
	if in.SLABreached > 0 {
		actions = append(actions, Action{
			Priority: 3, Severity: "high",
			Title:       "Resolve SLA breaches",
			Description: pluralf("%d remediation item has", "%d remediation items have", in.SLABreached) + " breached their SLA deadline.",
		})
	}
	if in.MonitorCount == 0 && in.UniqueTargets > 0 {
		actions = append(actions, Action{
			Priority: 4, Severity: "medium",
			Title:       "Enable continuous monitoring",
			Description: "No active monitors configured. Set up rescans to detect new attack surface changes.",
		})
	}
	if in.RemItems == 0 && (in.FindingCounts["critical"]+in.FindingCounts["high"]) > 0 {
		actions = append(actions, Action{
			Priority: 5, Severity: "medium",
			Title:       "Start tracking remediations",
			Description: "Critical and high findings have no remediation items. Use 'Promote Critical & High' to begin tracking.",
		})
	}
	if len(actions) == 0 {
		actions = append(actions, Action{
			Priority: 1, Severity: "low",
			Title:       "Maintain posture",
			Description: "No critical actions required. Continue scheduled scans and monitor for new findings.",
		})
	}
	if len(actions) > 5 {
		actions = actions[:5]
	}
	return actions
}

func pluralf(singular, plural string, n int) string {
	if n == 1 {
		return fmt.Sprintf(singular, n)
	}
	return fmt.Sprintf(plural, n)
}
