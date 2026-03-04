package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
)

const maxIterations = 20

// EventType for WebSocket streaming
type EventType string

const (
	EventThinking   EventType = "thinking"
	EventToolCall   EventType = "tool_call"
	EventToolResult EventType = "tool_result"
	EventMessage    EventType = "message"
	EventComplete   EventType = "complete"
	EventError      EventType = "error"
)

// Event is a real-time update sent to the frontend
type Event struct {
	ID        string      `json:"id"`
	Type      EventType   `json:"type"`
	FlowID    string      `json:"flow_id"`
	TaskID    string      `json:"task_id,omitempty"`
	Content   string      `json:"content"`
	Metadata  interface{} `json:"metadata,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// EventHandler is called for each agent event (for WebSocket streaming)
type EventHandler func(Event)

// Structured Brain for Mirage 2.0
type Brain struct {
	Leads      []string `json:"leads"`      // Unconfirmed interests
	Findings   []string `json:"findings"`   // Confirmed bugs
	Exclusions []string `json:"exclusions"` // Dead ends
}

// SwarmAgentSpec is a richer agent dispatch format from the Planner
type SwarmAgentSpec struct {
	Type     string `json:"type"`               // e.g. "SQLi", "XSS", "Code Review"
	Target   string `json:"target,omitempty"`   // specific endpoint/param
	Context  string `json:"context,omitempty"`  // what the planner observed
	Priority string `json:"priority,omitempty"` // "critical", "high", "medium", "low"
}

// Orchestrator is the main AI agent that plans and executes pentest tasks
type Orchestrator struct {
	llmProvider  llm.Provider
	toolRegistry *tools.Registry
	queries      *database.Queries
	onEvent      EventHandler
}

// NewOrchestrator creates the main agent
func NewOrchestrator(provider llm.Provider, registry *tools.Registry, db *sql.DB) *Orchestrator {
	return &Orchestrator{
		llmProvider:  provider,
		toolRegistry: registry,
		queries:      database.NewQueries(db),
		onEvent:      func(e Event) {}, // no-op default
	}
}

// SetEventHandler sets the callback for real-time events
func (o *Orchestrator) SetEventHandler(handler EventHandler) {
	o.onEvent = handler
}

// RunFlow executes a complete penetration testing flow using concurrent agents
func (o *Orchestrator) RunFlow(ctx context.Context, flowID uuid.UUID, userPrompt string) error {
	flow, err := o.queries.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("failed to get flow: %w", err)
	}

	// Create the main task
	task, err := o.queries.CreateTask(flowID, "Penetration Test", userPrompt)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	if err := o.queries.UpdateTaskStatus(task.ID, models.TaskStatusRunning, ""); err != nil {
		return err
	}

	var brain Brain
	var brainMu sync.Mutex

	historicalCtx, _ := o.queries.GetHistoricalContext(flow.Target)

	// ==========================================
	// PHASE 1: RECONNAISSANCE
	// ==========================================
	reconSubtask, err := o.queries.CreateSubTask(task.ID, "Phase 1: Reconnaissance", "Map attack surface", models.AgentTypeOrchestrator)
	if err != nil {
		return err
	}

	o.toolRegistry.AddUpdateBrainTool(func(category, note string) {
		brainMu.Lock()
		switch category {
		case "lead":
			brain.Leads = append(brain.Leads, note)
		case "finding":
			brain.Findings = append(brain.Findings, note)
			// Mirage 2.0: Save to Actions table for permanent record
			o.queries.CreateAction(reconSubtask.ID, models.ActionTypeReport, "promoted_lead", note, "success")

			// Mirage 2.0: Auto-report to Findings Tab (Live Stream)
			o.emit(flowID.String(), Event{
				Type:    EventToolResult,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("## Discovery: %s\n**Severity**: High\n\nAutomatically promoted from Brain Lead.", note),
				Metadata: map[string]interface{}{
					"tool": "report_findings",
				},
			})
		case "exclusion":
			brain.Exclusions = append(brain.Exclusions, note)
		default:
			brain.Leads = append(brain.Leads, note)
		}
		brainMu.Unlock()

		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧠 Brain Synapse [%s]: %s", category, note),
		})
	})

	o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🚀 Initiating Phase 1: Reconnaissance"})

	reconPrompt := buildPhasePrompt("RECONNAISSANCE", "Analyze the user's request. Prioritize the specific tools and techniques they asked for (e.g. ffuf, nuclei). Do NOT run nmap or full port scans unless port scanning is explicitly requested or necessary. Map the attack surface relevant to the user's objective. Do NOT exploit.", flow.Target, userPrompt, historicalCtx)
	reconResult := o.runAgentLoop(ctx, flowID, task.ID, reconSubtask.ID, reconPrompt, "Start Recon.", &brain, &brainMu)

	// ==========================================
	// PHASE 2: INTELLIGENT PLANNER
	// ==========================================
	plannerSubtask, err := o.queries.CreateSubTask(task.ID, "Phase 2: Intelligent Planner", "Analyze and dispatch", models.AgentTypeOrchestrator)
	if err != nil {
		return err
	}
	o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🧠 Initiating Phase 2: Planner (Dynamic Swarm Construction)"})

	brainMu.Lock()
	plannerInput := "Recon Summary:\n" + reconResult + "\n\n🧠 Global Brain State:\n"
	bJSON, _ := json.MarshalIndent(brain, "", "  ")
	plannerInput += string(bJSON)
	brainMu.Unlock()

	plannerPrompt := buildPhasePrompt("PLANNER", `Analyze the Recon results and Brain State. Decide which specialized vulnerability agents to dispatch.

OUTPUT FORMAT: You MUST call complete_task with a JSON array of agent specs. Each spec has:
- "type": the attack category (e.g. "SQLi", "XSS", "SSRF", "Command Injection", "Code Review", "Auth Bypass", "Misconfigs")
- "target": the specific URL or parameter to attack (from recon data)
- "context": what you observed that makes this worth testing
- "priority": "critical", "high", "medium", or "low"

Example output for complete_task summary:
[{"type":"SQLi","target":"/api/user?id=1","context":"numeric param reflected in response","priority":"high"},{"type":"XSS","target":"/search?q=test","context":"unescaped query param in HTML","priority":"medium"}]

IMPORTANT: Only dispatch agents for REAL leads from recon. Do not guess. If source code is available, dispatch a "Code Review" agent.`, flow.Target, userPrompt, "")
	plannerResult := o.runAgentLoop(ctx, flowID, task.ID, plannerSubtask.ID, plannerPrompt, "Analyze and dispatch swarm:\n"+plannerInput, &brain, &brainMu)

	// Parse SwarmAgentSpec array (with fallback to plain string array)
	jsonStr := plannerResult
	if idx := findJSONStart(jsonStr); idx != -1 {
		jsonStr = jsonStr[idx:]
	}
	if idx := findJSONEnd(jsonStr); idx != -1 {
		jsonStr = jsonStr[:idx+1]
	}

	var agentSpecs []SwarmAgentSpec
	if err := json.Unmarshal([]byte(jsonStr), &agentSpecs); err != nil {
		// Fallback: try parsing as plain string array
		var vulnTypes []string
		if err2 := json.Unmarshal([]byte(jsonStr), &vulnTypes); err2 != nil {
			vulnTypes = []string{"XSS", "SQLi", "SSRF"}
		}
		for _, vt := range vulnTypes {
			agentSpecs = append(agentSpecs, SwarmAgentSpec{Type: vt, Priority: "medium"})
		}
	}

	o.emit(flowID.String(), Event{
		Type:     EventMessage,
		FlowID:   flowID.String(),
		TaskID:   task.ID.String(),
		Content:  fmt.Sprintf("📋 Planner dispatching %d specialized agents", len(agentSpecs)),
		Metadata: map[string]interface{}{"agents": agentSpecs},
	})

	// ==========================================
	// PHASE 3: DYNAMIC VULNERABILITY SWARM
	// ==========================================
	resultsChan := make(chan string, len(agentSpecs))
	var wg sync.WaitGroup
	for _, spec := range agentSpecs {
		wg.Add(1)
		go func(s SwarmAgentSpec) {
			defer wg.Done()
			st, _ := o.queries.CreateSubTask(task.ID, "Phase 3: "+s.Type, "Scan for "+s.Type, models.AgentTypeOrchestrator)

			instr := getToolingInstruction(s.Type)
			logic := "Logic-First: Test edge cases (//, ../, %2f), CRLF, and payload bypasses."

			// Build context-aware prompt
			agentContext := ""
			if s.Target != "" {
				agentContext += fmt.Sprintf("\nFOCUS TARGET: %s", s.Target)
			}
			if s.Context != "" {
				agentContext += fmt.Sprintf("\nPLANNER CONTEXT: %s", s.Context)
			}
			if s.Priority != "" {
				agentContext += fmt.Sprintf("\nPRIORITY: %s", s.Priority)
			}

			p := buildPhasePrompt("SWARM AGENT", fmt.Sprintf("Hunt for %s. %s\n%s%s", s.Type, instr, logic, agentContext), flow.Target, userPrompt, "")

			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("🐝 Swarm Agent [%s] deployed — Priority: %s", s.Type, s.Priority),
			})

			res := o.runAgentLoop(ctx, flowID, task.ID, st.ID, p, "Start "+s.Type+" hunt.", &brain, &brainMu)
			resultsChan <- fmt.Sprintf("### %s Findings:\n%s\n", s.Type, res)
		}(spec)
	}
	wg.Wait()
	close(resultsChan)

	var swarmResults string
	for r := range resultsChan {
		swarmResults += r + "\n"
	}

	// ==========================================
	// PHASE 4: PoC GENERATOR
	// ==========================================
	pocSubtask, _ := o.queries.CreateSubTask(task.ID, "Phase 4: PoC Generator", "Create reproducible evidence", models.AgentTypeReporter)
	o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🧪 Initiating Phase 4: PoC Generator (Validating Findings)"})

	// Build findings context from Brain
	brainMu.Lock()
	var findingsContext string
	if len(brain.Findings) > 0 {
		findingsContext = "CONFIRMED FINDINGS FROM BRAIN:\n"
		for i, f := range brain.Findings {
			findingsContext += fmt.Sprintf("%d. %s\n", i+1, f)
		}
	} else {
		findingsContext = "No confirmed findings in Brain. Review swarm results for potential issues."
	}
	brainMu.Unlock()

	pocPrompt := buildPhasePrompt("PoC_GENERATOR", `You are a Proof-of-Concept specialist. For each CONFIRMED finding:

1. Generate a **curl one-liner** that reproduces the vulnerability
2. Generate a **Python script** (standalone, using only 'requests' library) that:
   - Reproduces the vulnerability
   - Prints clear SUCCESS/FAIL output
   - Includes comments explaining each step
3. Estimate a **CVSS score** (0.0-10.0)
4. Write clear **reproduction steps** a human can follow

OUTPUT FORMAT (for each finding):
## PoC: [Finding Title]
**CVSS**: X.X | **Severity**: Critical/High/Medium/Low

### Curl
`+"```bash\ncurl ...\n```"+`

### Python
`+"```python\nimport requests\n...\n```"+`

### Steps to Reproduce
1. ...
2. ...

Use report_findings tool to submit each PoC individually. Use update_brain to mark findings as verified.`, flow.Target, userPrompt, "")

	pocInput := findingsContext + "\n\nSWARM RESULTS:\n" + swarmResults
	pocResult := o.runAgentLoop(ctx, flowID, task.ID, pocSubtask.ID, pocPrompt, "Generate PoCs for these findings:\n"+pocInput, &brain, &brainMu)

	// ==========================================
	// AGGREGATION
	// ==========================================
	finalReport := fmt.Sprintf("# Pentest Report for %s\n\n## Recon\n%s\n\n## Vulnerabilities\n%s\n\n## Reproducible Evidence (PoCs)\n%s", flow.Target, reconResult, swarmResults, pocResult)
	o.queries.UpdateTaskStatus(task.ID, models.TaskStatusDone, finalReport)
	o.queries.UpdateFlowStatus(flowID, models.FlowStatusCompleted)
	o.emit(flowID.String(), Event{Type: EventComplete, FlowID: flowID.String(), TaskID: task.ID.String(), Content: finalReport})

	return nil
}

func (o *Orchestrator) runAgentLoop(ctx context.Context, flowID uuid.UUID, taskID uuid.UUID, subtaskID uuid.UUID, systemPrompt string, userPrompt string, brain *Brain, brainMu *sync.Mutex) string {
	o.queries.UpdateSubTaskStatus(subtaskID, models.SubTaskStatusRunning)

	var chatMsgs []models.ChatMessage
	chatMsgs = append(chatMsgs, models.ChatMessage{Role: "system", Content: systemPrompt})
	chatMsgs = append(chatMsgs, models.ChatMessage{Role: "user", Content: userPrompt})

	var lastResult string
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			return "Cancelled"
		default:
		}

		brainMu.Lock()
		bJSON, _ := json.Marshal(brain)
		brainMu.Unlock()

		currentMsgs := append([]models.ChatMessage{
			{Role: "system", Content: "CURRENT DYNAMIC BRAIN STATE (Read-Only):\n" + string(bJSON)},
		}, chatMsgs...)

		o.emit(flowID.String(), Event{
			Type:     EventThinking,
			FlowID:   flowID.String(),
			TaskID:   taskID.String(),
			Content:  "Thinking...",
			Metadata: map[string]interface{}{"subtask_id": subtaskID.String()},
		})

		resp, err := o.llmProvider.Complete(ctx, llm.CompletionRequest{
			Messages: currentMsgs,
			Tools:    o.toolRegistry.Definitions(),
		})

		if err != nil {
			o.emit(flowID.String(), Event{Type: EventError, FlowID: flowID.String(), TaskID: taskID.String(), Content: err.Error()})
			return "Error: " + err.Error()
		}

		// Convert LLM message to ChatMessage
		msg := models.ChatMessage{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		}
		chatMsgs = append(chatMsgs, msg)

		if len(resp.ToolCalls) > 0 {
			for _, tc := range resp.ToolCalls {
				o.emit(flowID.String(), Event{
					Type:    EventToolCall,
					FlowID:  flowID.String(),
					TaskID:  taskID.String(),
					Content: fmt.Sprintf("Calling tool: %s", tc.Name),
					Metadata: map[string]interface{}{
						"tool":       tc.Name,
						"args":       tc.Arguments,
						"subtask_id": subtaskID.String(),
					},
				})

				tool, ok := o.toolRegistry.Get(tc.Name)
				var res string
				if !ok {
					res = "Tool not found: " + tc.Name
				} else {
					res, _ = tool.Execute(ctx, json.RawMessage(tc.Arguments))
				}

				// Restore Action Persistence
				o.queries.CreateAction(subtaskID, models.ActionTypeCommand, tc.Arguments, res, "success")

				o.emit(flowID.String(), Event{
					Type:    EventToolResult,
					FlowID:  flowID.String(),
					TaskID:  taskID.String(),
					Content: res,
					Metadata: map[string]interface{}{
						"tool":       tc.Name,
						"subtask_id": subtaskID.String(),
					},
				})
				chatMsgs = append(chatMsgs, models.ChatMessage{Role: "tool", Content: res, ToolCallID: tc.ID})

				if tc.Name == "complete_task" {
					lastResult = res
					goto done
				}
			}
		} else {
			chatMsgs = append(chatMsgs, models.ChatMessage{Role: "user", Content: "Continue. Use tools or complete_task."})
		}
	}
	lastResult = "Max iterations reached"

done:
	o.queries.UpdateSubTaskStatus(subtaskID, models.SubTaskStatusCompleted)
	return lastResult
}

func (o *Orchestrator) emit(flowID string, event Event) {
	event.ID = uuid.New().String()
	event.FlowID = flowID
	event.Timestamp = time.Now()
	fmt.Printf("📡 Event [%s]: %s - %s\n", event.ID[:8], event.Type, event.Content[:min(30, len(event.Content))])
	o.onEvent(event)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findJSONStart(s string) int {
	for i, c := range s {
		if c == '[' || c == '{' {
			return i
		}
	}
	return -1
}

func findJSONEnd(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ']' || s[i] == '}' {
			return i
		}
	}
	return -1
}

func getToolingInstruction(vt string) string {
	switch vt {
	case "XSS":
		return "Use 'dalfox url <target>' and 'xsstrike -u <target>'. These are best-in-class for reflected, stored, and DOM XSS."
	case "SQLi":
		return "Use 'sqlmap -u <target> --batch'. If you suspect WAF, use '--tamper=space2comment'. For NoSQL, check if 'nosqlmap' is available or use custom 'ffuf' patterns."
	case "SSRF", "IDOR":
		return "Use 'ffuf' to fuzz for internal IP ranges or sensitive files. Use 'nuclei -t protocols/ssrf' for automated SSRF detection."
	case "Command Injection":
		return "Use 'commix -u <target> --level=3'. It is specialized for OS commanding and payload generation."
	case "LDAP Injection":
		return "Use 'ffuf' with LDAP-specific wordlists or 'nmap --script ldap-search'. Check for null-binds."
	case "NoSQL Injection":
		return "Use 'ffuf' to test for '$gt', '$ne' in JSON bodies. Targeted fuzzing is key here."
	case "Auth Bypass", "Broken Access Control":
		return "Use 'ffuf' to brute force IDs or 'hydra' for credential stuffing. Check 'nuclei' for known CVEs in the auth provider."
	case "Misconfigs", "CORS", "S3 Buckets":
		return "Use 'corsy -u <target>' for CORS flaws. Use 'nuclei' for cloud misconfigs and S3 bucket leakage."
	case "CMS Scan", "WordPress", "Joomla":
		return "Use 'nuclei -tags cms' or specific scanners like 'wpscan' if available to identify outdated plugins."
	default:
		return "Use best available tools (nmap, ffuf, nuclei). If a specific specialized tool is needed but not listed, try triggering it via 'execute_command' if you are confident it is installed."
	}
}

func buildPhasePrompt(phase string, instr string, target string, up string, hist string) string {
	return fmt.Sprintf("# PHASE: %s\nTarget: %s\nObjective: %s\n\nRules:\n1. Structured Memory: Use 'update_brain'.\n2. Stealth: Be professional.\n\n%s\nUser: %s", phase, target, instr, hist, up)
}
