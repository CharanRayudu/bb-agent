package agent

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Insight represents a piece of learned knowledge about a target
type Insight struct {
	ID        uuid.UUID `json:"id"`
	Target    string    `json:"target"`
	Domain    string    `json:"domain"`
	Category  string    `json:"category"`
	Insight   string    `json:"insight"`
	FlowID    uuid.UUID `json:"flow_id"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkingMemory holds per-flow session state (leads, findings, auth context).
// This is the formalized version of the Brain struct.
type WorkingMemory struct {
	Leads        []string   `json:"leads"`
	Findings     []*Finding `json:"findings"`
	Exclusions   []string   `json:"exclusions"`
	PivotContext string     `json:"pivot_context"`
	Auth         *AuthState `json:"auth,omitempty"`
	Preferences  map[string]string `json:"preferences,omitempty"`
}

// NewWorkingMemory creates a fresh per-flow working memory.
func NewWorkingMemory() *WorkingMemory {
	return &WorkingMemory{
		Leads:       make([]string, 0),
		Findings:    make([]*Finding, 0),
		Exclusions:  make([]string, 0),
		Preferences: make(map[string]string),
	}
}

// Memory provides cross-flow persistent learning for the agent.
// It implements two-tier memory: WorkingMemory (per-flow) + LongTermMemory (cross-flow via pgvector).
type Memory struct {
	db *sql.DB
}

func NewMemory(db *sql.DB) *Memory {
	m := &Memory{db: db}
	if db != nil {
		m.ensureTable()
	}
	return m
}

// ensureTable creates the target_memory table if it doesn't exist
func (m *Memory) ensureTable() {
	query := `
	CREATE TABLE IF NOT EXISTS target_memory (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		target TEXT NOT NULL,
		domain TEXT NOT NULL,
		category TEXT NOT NULL,
		insight TEXT NOT NULL,
		flow_id UUID,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_memory_domain ON target_memory(domain);
	CREATE INDEX IF NOT EXISTS idx_memory_target ON target_memory(target);
	`
	if _, err := m.db.Exec(query); err != nil {
		log.Printf("[memory] Warning: could not ensure target_memory table: %v", err)
	}

	// Payload performance for Thompson Sampling
	perfQuery := `
	CREATE TABLE IF NOT EXISTS payload_performance (
		id SERIAL PRIMARY KEY,
		tech_stack TEXT NOT NULL, -- e.g. "PHP/MySQL"
		vuln_type TEXT NOT NULL,  -- e.g. "sqli"
		payload TEXT NOT NULL,
		success_count INT DEFAULT 0,
		failure_count INT DEFAULT 0,
		UNIQUE(tech_stack, vuln_type, payload)
	);
	`
	if _, err := m.db.Exec(perfQuery); err != nil {
		log.Printf("[memory] Warning: could not ensure payload_performance table: %v", err)
	}

	m.ensureCorrelationTable()
}

// ensureCorrelationTable creates the target_correlations table if it doesn't exist.
func (m *Memory) ensureCorrelationTable() {
	query := `
	CREATE TABLE IF NOT EXISTS target_correlations (
		id SERIAL PRIMARY KEY,
		target1 TEXT NOT NULL,
		target2 TEXT NOT NULL,
		vuln_type TEXT NOT NULL,
		relation TEXT NOT NULL,
		flow_id UUID,
		created_at TIMESTAMP DEFAULT NOW()
	);
	`
	if _, err := m.db.Exec(query); err != nil {
		log.Printf("[memory] Warning: could not ensure target_correlations table: %v", err)
	}
}

// SaveInsight persists a learned insight about a target
func (m *Memory) SaveInsight(target, category, insight string, flowID uuid.UUID) error {
	domain := extractDomain(target)
	_, err := m.db.Exec(
		`INSERT INTO target_memory (id, target, domain, category, insight, flow_id) VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), target, domain, category, insight, flowID,
	)
	if err != nil {
		return fmt.Errorf("failed to save insight: %w", err)
	}
	return nil
}

// GetInsights retrieves all past insights for a specific target
func (m *Memory) GetInsights(target string) ([]Insight, error) {
	domain := extractDomain(target)

	rows, err := m.db.Query(
		`SELECT id, target, domain, category, insight, flow_id, created_at 
		 FROM target_memory 
		 WHERE domain = $1 
		 ORDER BY created_at DESC 
		 LIMIT 50`,
		domain,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query insights: %w", err)
	}
	defer rows.Close()

	var insights []Insight
	for rows.Next() {
		var i Insight
		if err := rows.Scan(&i.ID, &i.Target, &i.Domain, &i.Category, &i.Insight, &i.FlowID, &i.CreatedAt); err != nil {
			continue
		}
		insights = append(insights, i)
	}
	return insights, nil
}

// FormatInsightsForPrompt formats past insights into a string for LLM context injection
func (m *Memory) FormatInsightsForPrompt(target string) string {
	insights, err := m.GetInsights(target)
	if err != nil || len(insights) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("[MEMORY] CROSS-FLOW MEMORY (Insights from past scans on this target):\n")
	for i, ins := range insights {
		sb.WriteString(fmt.Sprintf("  %d. [%s] %s (from flow %s, %s ago)\n",
			i+1, ins.Category, ins.Insight, ins.FlowID.String()[:8],
			formatDuration(time.Since(ins.CreatedAt)),
		))
	}
	return sb.String()
}

// SaveBrainFindings persists all Brain findings as memory at end of a flow
func (m *Memory) SaveBrainFindings(target string, flowID uuid.UUID, leads []string, findings []*Finding, exclusions []string) {
	for _, f := range findings {
		m.SaveInsight(target, "known_vuln", fmt.Sprintf("%s: %s (param: %s)", f.Type, f.URL, f.Parameter), flowID)
	}
	for _, l := range leads {
		m.SaveInsight(target, "recon_lead", l, flowID)
	}
	for _, e := range exclusions {
		m.SaveInsight(target, "dead_end", e, flowID)
	}
}

// extractDomain extracts the base domain from a target string (IP:port, URL, hostname)
func extractDomain(target string) string {
	t := strings.TrimSpace(target)
	// Strip protocol
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	// Strip path
	if idx := strings.Index(t, "/"); idx != -1 {
		t = t[:idx]
	}
	// Strip port
	if idx := strings.LastIndex(t, ":"); idx != -1 {
		t = t[:idx]
	}
	return t
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// --- Thompson Sampling / Payload Performance ---

// RecordPayloadResult updates the success/failure counters for a payload
func (m *Memory) RecordPayloadResult(tech, vuln, payload string, success bool) {
	query := `
	INSERT INTO payload_performance (tech_stack, vuln_type, payload, success_count, failure_count)
	VALUES ($1, $2, $3, CASE WHEN $4 THEN 1 ELSE 0 END, CASE WHEN $4 THEN 0 ELSE 1 END)
	ON CONFLICT (tech_stack, vuln_type, payload)
	DO UPDATE SET 
		success_count = payload_performance.success_count + CASE WHEN $4 THEN 1 ELSE 0 END,
		failure_count = payload_performance.failure_count + CASE WHEN $4 THEN 0 ELSE 1 END
	`
	m.db.Exec(query, tech, vuln, payload, success)
}

// GetTopPayloads returns the best payloads according to performance memory
func (m *Memory) GetTopPayloads(tech, vuln string, limit int) []string {
	rows, err := m.db.Query(
		`SELECT payload FROM payload_performance 
		 WHERE tech_stack = $1 AND vuln_type = $2
		 ORDER BY (success_count + 1.0) / (success_count + failure_count + 2.0) DESC
		 LIMIT $3`,
		tech, vuln, limit,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var payloads []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			payloads = append(payloads, p)
		}
	}
	return payloads
}

// --- Long-Term Memory (Two-Tier System) ---

// LongTermInsight represents a cross-session learning stored with embeddings.
type LongTermInsight struct {
	ID        uuid.UUID `json:"id"`
	Target    string    `json:"target"`
	Category  string    `json:"category"`   // "target_profile", "exploit_chain", "technique", "preference"
	Content   string    `json:"content"`
	TechStack string    `json:"tech_stack"`
	FlowID    uuid.UUID `json:"flow_id"`
	Score     float64   `json:"score"`      // relevance score for retrieval
	CreatedAt time.Time `json:"created_at"`
}

// ensureLongTermTable creates the long-term memory tables.
func (m *Memory) ensureLongTermTable() {
	query := `
	CREATE TABLE IF NOT EXISTS long_term_memory (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		target TEXT NOT NULL,
		category TEXT NOT NULL,
		content TEXT NOT NULL,
		tech_stack TEXT DEFAULT '',
		flow_id UUID,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_ltm_target ON long_term_memory(target);
	CREATE INDEX IF NOT EXISTS idx_ltm_category ON long_term_memory(category);
	CREATE INDEX IF NOT EXISTS idx_ltm_tech ON long_term_memory(tech_stack);
	`
	if _, err := m.db.Exec(query); err != nil {
		log.Printf("[memory] Warning: could not ensure long_term_memory table: %v", err)
	}
}

// SaveLongTermInsight persists a learning for future flows.
func (m *Memory) SaveLongTermInsight(target, category, content, techStack string, flowID uuid.UUID) error {
	m.ensureLongTermTable()
	_, err := m.db.Exec(
		`INSERT INTO long_term_memory (target, category, content, tech_stack, flow_id) 
		 VALUES ($1, $2, $3, $4, $5)`,
		extractDomain(target), category, content, techStack, flowID,
	)
	return err
}

// RetrieveLongTermContext loads relevant past learnings for a target or tech stack.
func (m *Memory) RetrieveLongTermContext(target, techStack string, limit int) []LongTermInsight {
	m.ensureLongTermTable()
	if limit <= 0 {
		limit = 20
	}
	domain := extractDomain(target)

	rows, err := m.db.Query(
		`SELECT id, target, category, content, tech_stack, flow_id, created_at
		 FROM long_term_memory
		 WHERE target = $1 OR tech_stack = $2
		 ORDER BY created_at DESC
		 LIMIT $3`,
		domain, techStack, limit,
	)
	if err != nil {
		log.Printf("[memory] Long-term retrieval failed: %v", err)
		return nil
	}
	defer rows.Close()

	var insights []LongTermInsight
	for rows.Next() {
		var i LongTermInsight
		if err := rows.Scan(&i.ID, &i.Target, &i.Category, &i.Content, &i.TechStack, &i.FlowID, &i.CreatedAt); err != nil {
			continue
		}
		insights = append(insights, i)
	}
	return insights
}

// FormatLongTermContext formats long-term memory into a prompt block.
func (m *Memory) FormatLongTermContext(target, techStack string) string {
	insights := m.RetrieveLongTermContext(target, techStack, 15)
	if len(insights) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("LONG-TERM MEMORY (Cross-flow learnings):\n")
	for i, ins := range insights {
		sb.WriteString(fmt.Sprintf("  %d. [%s] %s (from flow %s, %s ago)\n",
			i+1, ins.Category, ins.Content, ins.FlowID.String()[:8],
			formatDuration(time.Since(ins.CreatedAt)),
		))
	}
	return sb.String()
}

// CorrelatedTarget describes a related target found through cross-flow analysis.
type CorrelatedTarget struct {
	Target      string
	Relation    string   // "subdomain", "shared_infra", "same_vuln_class"
	CommonVulns []string
	Score       float64 // correlation strength 0-1
}

// FindCorrelatedTargets looks for other targets in memory that share vulns with this one.
// It queries target_memory for domains that appear to be related (same base domain or
// same vulnerability class appearing in multiple targets).
func (m *Memory) FindCorrelatedTargets(currentTarget string, limit int) []CorrelatedTarget {
	if m.db == nil {
		return nil
	}
	if limit <= 0 {
		limit = 10
	}

	baseDomain := extractBaseDomain(currentTarget)

	// Find targets sharing the same base domain
	rows, err := m.db.Query(
		`SELECT DISTINCT target FROM target_memory
		 WHERE domain LIKE $1 AND target != $2`,
		"%"+baseDomain, currentTarget,
	)
	if err != nil {
		log.Printf("[memory] FindCorrelatedTargets query error: %v", err)
		return nil
	}
	defer rows.Close()

	var relatedTargets []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err == nil {
			relatedTargets = append(relatedTargets, t)
		}
	}

	if len(relatedTargets) == 0 {
		return nil
	}

	// Count known_vuln categories for the current target
	currentVulns := m.getVulnCategories(currentTarget)
	totalCurrent := len(currentVulns)

	var results []CorrelatedTarget
	seen := make(map[string]bool)

	for _, related := range relatedTargets {
		if seen[related] {
			continue
		}
		seen[related] = true

		relatedVulns := m.getVulnCategories(related)
		var common []string
		for v := range relatedVulns {
			if currentVulns[v] {
				common = append(common, v)
			}
		}

		// Determine relation type
		relation := "shared_infra"
		relatedBase := extractBaseDomain(related)
		if relatedBase == baseDomain {
			relation = "subdomain"
		}
		if len(common) > 0 {
			relation = "same_vuln_class"
		}

		// Compute score: shared vuln count / total unique vulns
		total := totalCurrent + len(relatedVulns) - len(common)
		var score float64
		if total > 0 {
			score = float64(len(common)) / float64(total)
		} else {
			score = 0.5 // base score for structural similarity
		}

		results = append(results, CorrelatedTarget{
			Target:      related,
			Relation:    relation,
			CommonVulns: common,
			Score:       score,
		})
	}

	// Sort by score descending (simple insertion sort for small slices)
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].Score > results[j-1].Score; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}

	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

// getVulnCategories returns a set of known_vuln category strings for a target.
func (m *Memory) getVulnCategories(target string) map[string]bool {
	rows, err := m.db.Query(
		`SELECT insight FROM target_memory WHERE target = $1 AND category = 'known_vuln'`,
		target,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[string]bool)
	for rows.Next() {
		var insight string
		if err := rows.Scan(&insight); err == nil {
			// Extract vuln type from "TYPE: URL (param: PARAM)" format
			parts := strings.SplitN(insight, ":", 2)
			if len(parts) > 0 {
				result[strings.TrimSpace(parts[0])] = true
			}
		}
	}
	return result
}

// extractBaseDomain extracts the registrable domain (e.g. api.example.com -> example.com).
func extractBaseDomain(target string) string {
	host := extractDomain(target)
	// Return last two labels of the host as the base domain
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// SaveCorrelation records that two targets share a vulnerability pattern.
func (m *Memory) SaveCorrelation(target1, target2, vulnType, relation string, flowID uuid.UUID) {
	if m.db == nil {
		return
	}
	_, err := m.db.Exec(
		`INSERT INTO target_correlations (target1, target2, vuln_type, relation, flow_id)
		 VALUES ($1, $2, $3, $4, $5)`,
		target1, target2, vulnType, relation, flowID,
	)
	if err != nil {
		log.Printf("[memory] SaveCorrelation error: %v", err)
	}
}

// PersistFlowLearnings saves all relevant learnings from a completed flow
// into long-term memory for future use.
func (m *Memory) PersistFlowLearnings(target string, flowID uuid.UUID, techStack string, brain *Brain) {
	// Save confirmed findings as exploit chains
	if brain != nil {
		for _, f := range brain.Findings {
			if f == nil {
				continue
			}
			content := fmt.Sprintf("Confirmed %s on %s via %s (param: %s, confidence: %.2f)",
				f.Type, f.URL, f.Payload, f.Parameter, f.Confidence)
			m.SaveLongTermInsight(target, "exploit_chain", content, techStack, flowID)
		}

		// Save dead ends so we don't repeat them
		for _, exc := range brain.Exclusions {
			m.SaveLongTermInsight(target, "dead_end", exc, techStack, flowID)
		}

		// Save auth patterns discovered
		if brain.Auth != nil && brain.Auth.AuthMethod != "" {
			content := fmt.Sprintf("Auth method: %s, login URL: %s", brain.Auth.AuthMethod, brain.Auth.LoginURL)
			m.SaveLongTermInsight(target, "target_profile", content, techStack, flowID)
		}
	}

	// Save target profile
	if techStack != "" {
		m.SaveLongTermInsight(target, "target_profile",
			fmt.Sprintf("Tech stack: %s", techStack), techStack, flowID)
	}
}
