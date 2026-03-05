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

// Memory provides cross-flow persistent learning for the agent
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
	sb.WriteString("📚 CROSS-FLOW MEMORY (Insights from past scans on this target):\n")
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
