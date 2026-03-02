package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
)

const maxIterations = 50

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
	Type      EventType   `json:"type"`
	FlowID    string      `json:"flow_id"`
	TaskID    string      `json:"task_id,omitempty"`
	Content   string      `json:"content"`
	Metadata  interface{} `json:"metadata,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// EventHandler is called for each agent event (for WebSocket streaming)
type EventHandler func(Event)

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

// RunFlow executes a complete penetration testing flow
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

	// Create subtask for the orchestrator
	subtask, err := o.queries.CreateSubTask(task.ID, "Main Execution", userPrompt, models.AgentTypeOrchestrator)
	if err != nil {
		return fmt.Errorf("failed to create subtask: %w", err)
	}

	o.emit(flowID.String(), Event{
		Type:    EventThinking,
		FlowID:  flowID.String(),
		TaskID:  task.ID.String(),
		Content: "Starting penetration test analysis...",
	})

	// Build system prompt
	systemPrompt := buildSystemPrompt(flow.Target)

	// Initialize conversation
	messages := []models.ChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	// Agent loop
	var finalResult string
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Call LLM
		resp, err := o.llmProvider.Complete(llm.CompletionRequest{
			Messages: messages,
			Tools:    o.toolRegistry.Definitions(),
		})
		if err != nil {
			o.emit(flowID.String(), Event{Type: EventError, FlowID: flowID.String(), Content: err.Error()})
			return fmt.Errorf("LLM error on iteration %d: %w", i, err)
		}

		// If the LLM responded with text (no tool calls), we're done ONLY IF it actually used complete_task before.
		// Sometimes LLMs hit token limits and stop. We should prompt them to continue.
		if len(resp.ToolCalls) == 0 {
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: resp.Content,
			})

			// Add assistant message
			messages = append(messages, models.ChatMessage{
				Role:    "assistant",
				Content: resp.Content,
			})

			// Force it to continue or call complete_task
			messages = append(messages, models.ChatMessage{
				Role:    "user",
				Content: "Please continue your analysis or explicitly use the `complete_task` tool if you are finished.",
			})
			continue
		}

		// Add assistant message with tool calls to conversation
		assistantMsg := models.ChatMessage{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		}
		messages = append(messages, assistantMsg)

		// Execute each tool call
		for _, tc := range resp.ToolCalls {
			o.emit(flowID.String(), Event{
				Type:    EventToolCall,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("Calling %s", tc.Name),
				Metadata: map[string]string{
					"tool": tc.Name,
					"args": tc.Arguments,
				},
			})

			tool, ok := o.toolRegistry.Get(tc.Name)
			if !ok {
				toolResult := fmt.Sprintf("Error: unknown tool '%s'", tc.Name)
				messages = append(messages, models.ChatMessage{
					Role:       "tool",
					Content:    toolResult,
					ToolCallID: tc.ID,
				})
				continue
			}

			result, err := tool.Execute(ctx, json.RawMessage(tc.Arguments))
			if err != nil {
				result = fmt.Sprintf("Error executing %s: %s", tc.Name, err.Error())
			}

			// Record action in database
			actionType := models.ActionTypeCommand
			if tc.Name == "think" {
				actionType = models.ActionTypeAnalyze
			} else if tc.Name == "report_findings" {
				actionType = models.ActionTypeReport
			}

			status := "success"
			if err != nil {
				status = "error"
			}

			o.queries.CreateAction(subtask.ID, actionType, tc.Arguments, result, status)

			o.emit(flowID.String(), Event{
				Type:    EventToolResult,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: result,
				Metadata: map[string]string{
					"tool":   tc.Name,
					"status": status,
				},
			})

			// Add tool result to conversation
			messages = append(messages, models.ChatMessage{
				Role:       "tool",
				Content:    result,
				ToolCallID: tc.ID,
			})

			// Check if agent signaled completion
			if tc.Name == "complete_task" {
				finalResult = result
				goto done
			}
		}

		log.Printf("Agent iteration %d/%d complete (tokens: %d)", i+1, maxIterations, resp.Usage.TotalTokens)
	}

done:
	// Update task status
	taskStatus := models.TaskStatusDone
	if finalResult == "" {
		finalResult = "Task reached maximum iterations without explicit completion"
		taskStatus = models.TaskStatusFailed
	}

	o.queries.UpdateTaskStatus(task.ID, taskStatus, finalResult)
	o.queries.UpdateFlowStatus(flowID, models.FlowStatusCompleted)
	o.queries.UpdateSubTaskStatus(subtask.ID, models.SubTaskStatusCompleted)

	o.emit(flowID.String(), Event{
		Type:    EventComplete,
		FlowID:  flowID.String(),
		TaskID:  task.ID.String(),
		Content: finalResult,
	})

	return nil
}

func (o *Orchestrator) emit(flowID string, event Event) {
	event.Timestamp = time.Now()
	event.FlowID = flowID // Ensure flow ID is set

	// Persist to database
	fID, err := uuid.Parse(flowID)
	if err == nil {
		o.queries.CreateFlowEvent(fID, string(event.Type), event.Content, event.Metadata)
	}

	o.onEvent(event)
}

func buildSystemPrompt(target string) string {
	return fmt.Sprintf(`You are an autonomous penetration testing AI agent. Your role is to conduct thorough security assessments of target systems using professional penetration testing methodologies.

## Target
%s

## Your Capabilities
You have access to a sandboxed Docker container with the following security tools:
- **Reconnaissance**: nmap, masscan, amass, subfinder, httpx, dig, whois
- **Web Testing**: nikto, gobuster, dirb, sqlmap, wfuzz, nuclei, curl, wget
- **Exploitation**: metasploit-framework, searchsploit
- **Network**: netcat, socat, tcpdump
- **Scripting**: python3, bash

## Methodology
Follow a systematic penetration testing approach:
1. **Reconnaissance** — Discover hosts, open ports, running services, and OS/version info
2. **Enumeration** — Dig deeper into discovered services (web directories, DNS records, banners)
3. **Vulnerability Analysis** — Identify potential vulnerabilities using automated scanners and manual analysis
4. **Exploitation** — Attempt to exploit confirmed vulnerabilities (only with explicit authorization)
5. **Reporting** — Document all findings with severity ratings and remediation advice

## Rules
- Always start with passive/active reconnaissance before attempting exploitation
- Use the 'think' tool to plan your approach and analyze results before acting
- Use the 'report_findings' tool to document each significant discovery
- Use the 'complete_task' tool when you've finished the assessment
- Be thorough but efficient — avoid redundant scans
- If a scan produces no useful output, adapt your approach
- Never run destructive commands that could damage the target system
- Truncate very long outputs to focus on the most relevant information`, target)
}
