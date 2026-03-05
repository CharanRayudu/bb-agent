package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/agent/schema"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/agents/postexploit"
	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/bb-agent/mirage/internal/pipeline"
	"github.com/bb-agent/mirage/internal/queue"
	"github.com/bb-agent/mirage/internal/tools"
	"github.com/google/uuid"
)

const maxIterations = 20

// EventType for WebSocket streaming
type EventType string

const (
	EventThinking            EventType = "thinking"
	EventToolCall            EventType = "tool_call"
	EventToolResult          EventType = "tool_result"
	EventMessage             EventType = "message"
	EventComplete            EventType = "complete"
	EventError               EventType = "error"
	EventCausalNodeAddedWS   EventType = "causal_node_added"
	EventCausalNodeUpdatedWS EventType = "causal_node_updated"
	EventCausalEdgeAddedWS   EventType = "causal_edge_added"
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

// AuthState holds authentication context discovered during scanning
type AuthState struct {
	Cookies     map[string]string `json:"cookies,omitempty"`     // Session cookies (e.g. PHPSESSID)
	Credentials map[string]string `json:"credentials,omitempty"` // user:pass pairs
	LoginURL    string            `json:"loginURL,omitempty"`    // Detected login page URL
	AuthMethod  string            `json:"authMethod,omitempty"`  // "cookie", "basic", "bearer"
	Headers     map[string]string `json:"headers,omitempty"`     // Extra auth headers to inject
}

// Structured Brain for Mirage 2.0
type Brain struct {
	Leads        []string            `json:"leads"`                 // Unconfirmed interests
	Findings     []*Finding          `json:"findings"`              // Confirmed bugs
	Exclusions   []string            `json:"exclusions"`            // Dead ends
	PivotContext string              `json:"pivotContext"`          // Discovered context that unlocks new attack surface
	Tech         *TechStack          `json:"tech"`                  // Inferred technology stack
	Auth         *AuthState          `json:"auth,omitempty"`        // Authentication context for auth-aware scanning
	CausalGraph  *models.CausalGraph `json:"causalGraph,omitempty"` // DAG for non-monotonic evidence reasoning
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
	prompts      *config.Prompts
	bus          *EventBus
	conductor    *Conductor

	// Pipeline infrastructure
	pipeline *pipeline.State
	queueMgr *queue.Manager

	// Autonomy Infrastructure (Tier 1 & 2)
	memory      *Memory
	scope       *ScopeEngine
	rateLimiter *AdaptiveRateLimiter
	reporter    *ReportGenerator

	// Phase 13: The Visionary & The Ghost
	oobManager *OOBManager
	validator  *base.VisualValidator

	// Phase 14: The Phoenix Pivot & WAF Strategist
	strategist *WAFStrategist

	// Phase 15: The Mirage Singularity (Performance & Precision)
	workers map[string]*Worker
}

// NewOrchestrator creates the main agent
func NewOrchestrator(provider llm.Provider, registry *tools.Registry, db *sql.DB, prompts *config.Prompts) *Orchestrator {
	qm := queue.NewManager()
	// Register specialist queues with rate limits (items/sec)
	qm.Register("xss", 200, 10.0)
	qm.Register("sqli", 200, 10.0)
	qm.Register("ssrf", 100, 5.0)
	qm.Register("lfi", 100, 5.0)
	qm.Register("rce", 50, 3.0)
	qm.Register("xxe", 50, 3.0)
	qm.Register("openredirect", 100, 5.0)
	qm.Register("idor", 100, 5.0)
	qm.Register("csti", 50, 3.0)
	qm.Register("header_injection", 50, 3.0)
	qm.Register("protopollution", 50, 3.0)
	qm.Register("jwt", 50, 3.0)
	qm.Register("fileupload", 50, 3.0)
	// Pipeline/Recon agents
	qm.Register("apisecurity", 100, 5.0)
	qm.Register("assetdiscovery", 50, 5.0)
	qm.Register("authdiscovery", 50, 5.0)
	qm.Register("chaindiscovery", 50, 3.0)
	qm.Register("consolidation", 200, 20.0) // High throughput for the thinking agent
	qm.Register("dastysast", 100, 10.0)
	qm.Register("gospider", 50, 5.0)
	qm.Register("massassignment", 50, 3.0)
	qm.Register("nuclei", 50, 5.0)
	qm.Register("reporting", 10, 1.0)
	qm.Register("sqlmap", 20, 2.0)
	qm.Register("validation", 100, 10.0)
	// Special Class Agents
	qm.Register("cloudhunter", 50, 3.0)
	qm.Register("resourcehunter", 100, 10.0)
	qm.Register("wafevasion", 50, 5.0)
	qm.Register("businesslogic", 50, 3.0)
	// Elite Phase 8 Agents
	qm.Register("urlmaster", 10, 1.0)
	qm.Register("visualcrawler", 30, 2.0)

	o := &Orchestrator{
		llmProvider:  provider,
		toolRegistry: registry,
		onEvent:      func(e Event) {}, // no-op default
		prompts:      prompts,
		bus:          NewEventBus(),
		queueMgr:     qm,
		memory:       NewMemory(db),
		rateLimiter:  NewAdaptiveRateLimiter(20.0), // Start with 20 req/s
		reporter:     NewReportGenerator(),
		oobManager:   NewOOBManager(""), // Default Interactsh server
		validator:    base.NewVisualValidator(),
		strategist:   NewWAFStrategist(),
		workers:      make(map[string]*Worker),
	}

	if db != nil {
		o.queries = database.NewQueries(db)
	}

	// Register brain-integrated tools
	o.toolRegistry.AddPayloadMutationTool(provider)
	o.toolRegistry.AddVisualCrawlTool(func(ctx context.Context, url string) (string, error) {
		res, err := base.RunCrawl(ctx, url, base.DefaultBrowserOptions())
		if err != nil {
			return "", err
		}

		// Map results back to brain leads
		for _, link := range res.Links {
			o.bus.Emit(EventLeadDiscovered, fmt.Sprintf("Headless Lead: %s", link))
		}
		for _, input := range res.Inputs {
			o.bus.Emit(EventLeadDiscovered, fmt.Sprintf("Dynamic Input: %s on %s", input, url))
		}

		return fmt.Sprintf("Visual crawl complete. Discovered %d links and %d unique inputs/buttons.", len(res.Links), len(res.Inputs)), nil
	})

	// Register Standard Brain Tool (Event-Driven)
	o.toolRegistry.AddUpdateBrainTool(func(category, note string) {
		o.bus.Emit(EventBrainUpdate, map[string]string{
			"category": category,
			"note":     note,
		})
	})

	// Register Causal Graph tools for non-monotonic evidence reasoning
	o.toolRegistry.AddCausalGraphTools(
		func(id, nodeType, description string) {
			o.bus.Emit(EventCausalNodeAdded, &models.CausalNode{
				ID:          id,
				NodeType:    nodeType,
				Description: description,
				Status:      "PENDING",
				Confidence:  0.5, // Default confidence
			})
		},
		func(id, status string, confidence float64) {
			o.bus.Emit(EventCausalNodeUpdated, map[string]interface{}{
				"id":         id,
				"status":     status,
				"confidence": confidence,
			})
		},
		func(sourceID, targetID, label string) {
			o.bus.Emit(EventCausalEdgeAdded, &models.CausalEdge{
				SourceID: sourceID,
				TargetID: targetID,
				Label:    label,
			})
		},
	)

	// Register OOB tools for blind vulnerability detection
	o.toolRegistry.AddOOBTools(o.oobManager)

	// Phase 15: Initialize Specialist Workers for all registered specialist types
	// These are the "Continuous Hunters" that consume from queues
	specialistTypes := []string{"xss", "sqli", "ssrf", "rce", "lfi", "idor"}
	for _, st := range specialistTypes {
		q := o.queueMgr.Get(st)
		if q == nil {
			q = o.queueMgr.Register(st, 1000, 10.0)
		}

		// In a real implementation, we'd have a map of constructors
		// For now, we'll use the worker with the appropriate queue
		// The workers will be started in RunFlow
		o.workers[st] = NewWorker(nil, q, 5, func(f *Finding) {
			o.bus.Emit(EventFindingDiscovered, f.Evidence["note"])
		}, o)
	}

	return o
}

// GetQueueManager returns the specialist queue manager
func (o *Orchestrator) GetQueueManager() *queue.Manager {
	return o.queueMgr
}

// GetPipelineState returns the current pipeline state (nil if no scan running)
func (o *Orchestrator) GetPipelineState() *pipeline.State {
	return o.pipeline
}

// SetEventHandler sets the callback for real-time events
func (o *Orchestrator) SetEventHandler(handler EventHandler) {
	o.onEvent = handler
}

// SetConductor injects the Conductor dependency
func (o *Orchestrator) SetConductor(c *Conductor) {
	o.conductor = c
}

// GetEventBus returns the internal event bus
func (o *Orchestrator) GetEventBus() *EventBus {
	return o.bus
}

// RunFlow executes a complete penetration testing flow using concurrent agents
func (o *Orchestrator) RunFlow(ctx context.Context, flowID uuid.UUID, userPrompt string) error {
	flow, err := o.queries.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("failed to get flow: %w", err)
	}

	// Reset internal event bus for this flow to clear old subscribers
	o.bus.Reset()

	// Initialize pipeline state machine for this scan
	o.pipeline = pipeline.NewState(flowID.String())

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

	// Initialize scope guardrails for this flow
	o.scope = NewScopeEngine(flow.Target)

	// Fetch historical insights from cross-flow memory
	historicalCtx := o.memory.FormatInsightsForPrompt(flow.Target)
	if historicalCtx == "" {
		// Fallback to basic historical context if no memory found
		globalPast, _ := o.queries.GetHistoricalContext(flow.Target)
		if globalPast != "" {
			historicalCtx = "🕒 PAST FINDINGS ON THIS TARGET:\n" + globalPast
		}
	}

	// ==========================================
	// EVENT SUBSCRIPTIONS (Flow-Scoped)
	// ==========================================

	// Subscribe to pivot discoveries that warrant a pipeline restart
	o.bus.Subscribe(EventPivotDiscovered, func(data interface{}) {
		note := data.(string)
		brainMu.Lock()
		brain.PivotContext += "\n- " + note
		brainMu.Unlock()

		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🔄 [PIVOT DETECTED] New attack surface unlocked: %s. Initiating Iterative Feedback Loop...", note[:min(80, len(note))]),
		})

		// Reset pipeline to RECON to explore the newly discovered surface
		if o.pipeline != nil {
			o.pipeline.ResetToRecon(fmt.Sprintf("Pivot triggered by: %s", note))
		}
	})

	// Subscribe to brain updates via the update_brain tool
	o.bus.Subscribe(EventBrainUpdate, func(data interface{}) {
		params := data.(map[string]string)
		category := params["category"]
		note := params["note"]

		switch category {
		case "lead":
			o.bus.Emit(EventLeadDiscovered, note)
		case "finding":
			// Try to parse note as a structured Finding JSON
			var f Finding
			if err := json.Unmarshal([]byte(note), &f); err == nil {
				brainMu.Lock()
				brain.Findings = append(brain.Findings, &f)
				brainMu.Unlock()
				o.bus.Emit(EventFindingDiscovered, f.Type)
			} else {
				// Fallback: create a generic finding if it's just a string
				genF := &Finding{Type: "Finding", URL: flow.Target, Evidence: map[string]interface{}{"note": note}}
				brainMu.Lock()
				brain.Findings = append(brain.Findings, genF)
				brainMu.Unlock()
				o.bus.Emit(EventFindingDiscovered, note)
			}
		case "exclusion":
			o.bus.Emit(EventExclusionDiscovered, note)
		case "credentials", "pivot":
			o.bus.Emit(EventPivotDiscovered, note)
		case "tech":
			brainMu.Lock()
			if brain.Tech == nil {
				brain.Tech = DefaultTechStack()
			}
			o.updateTechStackFromNote(brain.Tech, note)
			brainMu.Unlock()
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("🛡️ Technology Stack Identified: %s", note),
				Metadata: map[string]interface{}{
					"tech_stack": brain.Tech,
				},
			})
			o.bus.Emit("EventTechStackDiscovered", brain.Tech)
		default:
			o.bus.Emit(EventLeadDiscovered, note)
		}
	})

	o.bus.Subscribe(EventLeadDiscovered, func(data interface{}) {
		note := data.(string)
		brainMu.Lock()
		brain.Leads = append(brain.Leads, note)
		brainMu.Unlock()
		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧠 Brain Synapse [lead]: %s", note),
		})
	})

	o.bus.Subscribe(EventFindingDiscovered, func(data interface{}) {
		note := data.(string)
		// Findings are already appended in the EventBrainUpdate handler for consistency
		o.emit(flowID.String(), Event{
			Type:    EventToolResult,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("## Discovery: %s\n**Severity**: High\n\nAutomatically promoted from Brain Lead.", note),
			Metadata: map[string]interface{}{
				"tool": "report_findings",
			},
		})

		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧠 Brain Synapse [finding]: %s", note),
		})
	})

	o.bus.Subscribe(EventExclusionDiscovered, func(data interface{}) {
		note := data.(string)
		brainMu.Lock()
		brain.Exclusions = append(brain.Exclusions, note)
		brainMu.Unlock()
		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧠 Brain Synapse [exclusion]: %s", note),
		})
	})

	o.bus.Subscribe(EventCausalNodeAdded, func(data interface{}) {
		node := data.(*models.CausalNode)
		brainMu.Lock()
		if brain.CausalGraph == nil {
			brain.CausalGraph = &models.CausalGraph{
				Nodes: make(map[string]*models.CausalNode),
			}
		}
		brain.CausalGraph.Nodes[node.ID] = node
		brainMu.Unlock()
		o.emit(flowID.String(), Event{
			Type:    EventCausalNodeAddedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧬 Causal Graph: Added node [%s] %s", node.NodeType, node.ID),
			Metadata: map[string]interface{}{
				"id":          node.ID,
				"node_type":   node.NodeType,
				"description": node.Description,
				"status":      node.Status,
				"confidence":  node.Confidence,
			},
		})
	})

	o.bus.Subscribe(EventCausalNodeUpdated, func(data interface{}) {
		params := data.(map[string]interface{})
		id := params["id"].(string)
		status := params["status"].(string)
		confidence := params["confidence"].(float64)

		brainMu.Lock()
		if brain.CausalGraph != nil {
			if node, ok := brain.CausalGraph.Nodes[id]; ok {
				if status != "" {
					node.Status = status
				}
				node.Confidence = confidence
			}
		}
		brainMu.Unlock()
		o.emit(flowID.String(), Event{
			Type:    EventCausalNodeUpdatedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧬 Causal Graph: Updated node %s (Status: %s, Confidence: %.2f)", id, status, confidence),
			Metadata: map[string]interface{}{
				"id":         id,
				"status":     status,
				"confidence": confidence,
			},
		})
	})

	o.bus.Subscribe(EventCausalEdgeAdded, func(data interface{}) {
		edge := data.(*models.CausalEdge)
		brainMu.Lock()
		if brain.CausalGraph == nil {
			brain.CausalGraph = &models.CausalGraph{
				Nodes: make(map[string]*models.CausalNode),
			}
		}
		brain.CausalGraph.Edges = append(brain.CausalGraph.Edges, *edge)
		brainMu.Unlock()
		o.emit(flowID.String(), Event{
			Type:    EventCausalEdgeAddedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("🧬 Causal Graph: Added relationship %s --[%s]--> %s", edge.SourceID, edge.Label, edge.TargetID),
			Metadata: map[string]interface{}{
				"source_id": edge.SourceID,
				"target_id": edge.TargetID,
				"label":     edge.Label,
			},
		})
	})

	// ==========================================
	// ITERATIVE FEEDBACK LOOP (Max 3 Loops)
	// ==========================================
	const maxLoops = 3
	loopTriggered := false
	var resetMu sync.Mutex

	// Update pivot discovery to also trigger loop reset
	o.bus.Subscribe(EventPivotDiscovered, func(data interface{}) {
		resetMu.Lock()
		loopTriggered = true
		resetMu.Unlock()
	})

	for loopCount := 1; loopCount <= maxLoops; loopCount++ {
		// Reset trigger for each loop iteration until it's set again
		resetMu.Lock()
		loopTriggered = false
		resetMu.Unlock()

		// ==========================================
		// PIPELINE: Start/Reset → RECONNAISSANCE
		// ==========================================
		if loopCount == 1 {
			if err := o.pipeline.Start(); err != nil {
				log.Printf("[pipeline] Failed to start: %v", err)
			}
		} else {
			if err := o.pipeline.ResetToRecon(fmt.Sprintf("Iterative Loop %d triggered by pivot discovery", loopCount)); err != nil {
				log.Printf("[pipeline] Failed to reset to recon: %v", err)
			}
		}

		o.emitPipelineEvent(flowID.String(), task.ID.String())

		reconSubtask, err := o.queries.CreateSubTask(task.ID, "Phase 1: Reconnaissance", "Map attack surface", models.AgentTypeOrchestrator)
		if err != nil {
			return err
		}

		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🚀 Initiating Phase 1: Reconnaissance"})

		reconPrompt := o.prompts.BuildPhasePrompt("RECONNAISSANCE", o.prompts.Phases.Recon, flow.Target, userPrompt, historicalCtx)

		reconCtx, cancelRecon := context.WithCancel(ctx)
		defer cancelRecon()
		if o.conductor != nil {
			o.conductor.RegisterAgent(reconSubtask.ID, "Reconnaissance", flow.Target, cancelRecon)
			defer o.conductor.DeregisterAgent(reconSubtask.ID, StatusComplete)
		}

		reconResult := o.runAgentLoop(reconCtx, flowID, task.ID, reconSubtask.ID, reconPrompt, "Start Recon.", &brain, &brainMu)

		// ==========================================
		// PHASE 1.5: SPA DEEP CRAWL (Headless Discovery)
		// ==========================================
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🕷️ Phase 1.5: SPA Deep Crawl (Headless Browser Discovery)"})

		crawlCtx, cancelCrawl := context.WithTimeout(ctx, 30*time.Second)
		crawlResults, crawlErr := base.RunCrawl(crawlCtx, flow.Target, base.DefaultBrowserOptions())
		cancelCrawl()

		var spaSummary string
		if crawlErr != nil {
			spaSummary = fmt.Sprintf("SPA crawl skipped: %v", crawlErr)
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "⚠️ SPA crawl failed (target may not support headless browsing). Continuing..."})
		} else {
			// Inject discovered leads into the Brain
			brainMu.Lock()
			for _, link := range crawlResults.Links {
				brain.Leads = append(brain.Leads, fmt.Sprintf("[SPA] Dynamic Link: %s", link))
			}
			for _, input := range crawlResults.Inputs {
				brain.Leads = append(brain.Leads, fmt.Sprintf("[SPA] Dynamic Input: %s on %s", input, flow.Target))
			}
			brainMu.Unlock()

			spaSummary = fmt.Sprintf("SPA crawl discovered %d dynamic links and %d interactive inputs.", len(crawlResults.Links), len(crawlResults.Inputs))
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("🕷️ %s", spaSummary),
			})
		}

		reconResult += "\n\nSPA DEEP CRAWL RESULTS:\n" + spaSummary

		// ==========================================
		// PIPELINE: RECON → DISCOVERY (Strategy/Planner)
		// ==========================================
		if err := o.pipeline.Advance("Recon complete", map[string]interface{}{
			"leads_found": len(brain.Leads),
		}); err != nil {
			log.Printf("[pipeline] Advance to DISCOVERY failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		// ==========================================
		// PIPELINE: DISCOVERY → STRATEGY (Planner)
		// ==========================================
		if err := o.pipeline.Advance("Discovery phase (combined with Strategy)", nil); err != nil {
			log.Printf("[pipeline] Advance to STRATEGY failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		plannerSubtask, err := o.queries.CreateSubTask(task.ID, "Phase 2: Intelligent Planner", "Analyze and dispatch", models.AgentTypeOrchestrator)
		if err != nil {
			return err
		}
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🧠 Initiating Phase 2: Planner (Dynamic Swarm Construction)"})

		brainMu.Lock()
		plannerInput := "RECON SUMMARY:\n" + reconResult + "\n\n🧠 BRAIN LEADS (LEADS TO CONSOLIDATE):\n"
		bJSON, _ := json.MarshalIndent(brain, "", "  ")
		plannerInput += string(bJSON)
		brainMu.Unlock()

		plannerPrompt := o.prompts.BuildPhasePrompt("THINKING & CONSOLIDATION", o.prompts.Phases.Planner, flow.Target, userPrompt, "")

		plannerCtx, cancelPlanner := context.WithCancel(ctx)
		defer cancelPlanner()
		if o.conductor != nil {
			o.conductor.RegisterAgent(plannerSubtask.ID, "Thinking & Consolidation", flow.Target, cancelPlanner)
			defer o.conductor.DeregisterAgent(plannerSubtask.ID, StatusComplete)
		}

		plannerResult := o.runAgentLoop(plannerCtx, flowID, task.ID, plannerSubtask.ID, plannerPrompt, "Consolidate these leads and dispatch specialists:\n"+plannerInput, &brain, &brainMu)

		// Schema Validation: Parse planner output with structured validation
		var agentSpecs []SwarmAgentSpec
		plannerOutput, parseErr := schema.Parse[schema.PlannerOutput](plannerResult)
		if parseErr != nil {
			// Schema validation failed — log the error and fall back to defaults
			log.Printf("[schema] Planner output validation failed: %v", parseErr)
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("⚠️ Planner output failed schema validation: %v. Using default specialist dispatch.", parseErr),
			})
			agentSpecs = []SwarmAgentSpec{
				{Type: "XSS", Priority: "high"},
				{Type: "SQLi", Priority: "high"},
				{Type: "SSRF", Priority: "medium"},
			}
		} else {
			// Convert schema specs to orchestrator specs
			for _, spec := range plannerOutput.Specs {
				agentSpecs = append(agentSpecs, SwarmAgentSpec{
					Type:     spec.Type,
					Target:   spec.Target,
					Context:  spec.Context,
					Priority: spec.Priority,
				})
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
		// PIPELINE: STRATEGY → EXPLOITATION (Swarm)
		// ==========================================
		if err := o.pipeline.Advance("Strategy complete, dispatching specialists", map[string]interface{}{
			"specialists_dispatched": len(agentSpecs),
		}); err != nil {
			log.Printf("[pipeline] Advance to EXPLOITATION failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		// Route items into specialist queues (for future Worker consumption)
		for _, spec := range agentSpecs {
			queueName := normalizeSpecialistName(spec.Type)
			payload := map[string]interface{}{
				"type":     spec.Type,
				"target":   spec.Target,
				"context":  spec.Context,
				"priority": spec.Priority,
			}
			if err := o.queueMgr.Route(queueName, payload, flowID.String()); err != nil {
				log.Printf("[queue] Route to %s failed (no queue registered), using direct execution: %v", queueName, err)
			}
		}

		// Emit queue metrics to frontend
		o.emitQueueStats(flowID.String(), task.ID.String())

		// Start background specialists for this flow
		for _, w := range o.workers {
			w.Start(ctx)
		}
		defer func() {
			for _, w := range o.workers {
				w.Stop()
			}
		}()

		// Enqueue tasks for workers
		ragClient := NewRAGClient("")
		for _, spec := range agentSpecs {
			// Query RAG Knowledge Base for context
			ragQuery := fmt.Sprintf("Best payloads and bypass techniques for %s testing on %s", spec.Type, spec.Target)
			if brain.Tech != nil {
				if brain.Tech.Lang != "" {
					ragQuery += fmt.Sprintf(" backend:%s", brain.Tech.Lang)
				}
				if brain.Tech.DB != "" {
					ragQuery += fmt.Sprintf(" database:%s", brain.Tech.DB)
				}
			}

			ragCtx, cancelRag := context.WithTimeout(ctx, 10*time.Second)
			ragContext, err := ragClient.RetrieveKnowledge(ragCtx, ragQuery, 3)
			cancelRag()

			enhancedContext := spec.Context
			if err == nil && ragContext != "" {
				enhancedContext += "\n\n" + ragContext
				o.emit(flowID.String(), Event{
					Type:    EventMessage,
					FlowID:  flowID.String(),
					TaskID:  task.ID.String(),
					Content: fmt.Sprintf("📚 Enhancing %s agent with payloads from RAG Knowledge Base.", spec.Type),
				})
			}

			o.queueMgr.Route(spec.Type, map[string]interface{}{
				"target":   spec.Target,
				"context":  enhancedContext,
				"priority": spec.Priority,
			}, flowID.String())
		}

		// Wait for queues to drain or flow timeout
		o.queueMgr.DrainAll(30 * time.Minute)

		resetMu.Lock()
		shouldLoop := loopTriggered
		resetMu.Unlock()

		// If a specialist found a credential, break immediate phase and restart loop
		if shouldLoop {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "⚠️ Interrupting current validation phase to start new Iterative Recon loop."})
			continue
		}

		var swarmResults string = "Asynchronous swarm analysis completed."

		// ==========================================
		// PIPELINE: EXPLOITATION → VALIDATION (PoC Generator)
		// ==========================================
		if err := o.pipeline.Advance("Exploitation complete", map[string]interface{}{
			"swarm_agents": len(agentSpecs),
			"findings":     len(brain.Findings),
		}); err != nil {
			log.Printf("[pipeline] Advance to VALIDATION failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		pocSubtask, _ := o.queries.CreateSubTask(task.ID, "Phase 4: PoC Generator", "Create reproducible evidence", models.AgentTypeReporter)
		// ==========================================
		// PHASE 4: POST-EXPLOITATION (Escalation)
		// ==========================================
		hasCritical := false
		var criticalFinding *Finding
		for _, f := range brain.Findings {
			lowerSev := strings.ToLower(f.Severity)
			if lowerSev == "critical" || lowerSev == "high" {
				hasCritical = true
				criticalFinding = f
				break
			}
		}

		if hasCritical {
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("🚀 [POST-EXPLOIT] High-impact vulnerability confirmed (%s). Escalating...", criticalFinding.Type),
			})

			peSubtask, _ := o.queries.CreateSubTask(task.ID, "Phase 4: Post-Exploitation", "Escalate confirmed vulnerability", models.AgentTypeExecutor)
			peAgent := postexploit.New()
			pePrompt := peAgent.BuildPrompt(flow.Target, fmt.Sprintf("%s at %s", criticalFinding.Type, criticalFinding.URL), userPrompt)
			peCtx, cancelPe := context.WithCancel(ctx)
			defer cancelPe()
			if o.conductor != nil {
				o.conductor.RegisterAgent(peSubtask.ID, "Post-Exploit", flow.Target, cancelPe)
				defer o.conductor.DeregisterAgent(peSubtask.ID, StatusComplete)
			}

			o.runAgentLoop(peCtx, flowID, task.ID, peSubtask.ID, pePrompt, "Escalate this finding:\n"+criticalFinding.Type+" at "+criticalFinding.URL, &brain, &brainMu)
		}

		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "🧪 Initiating Phase 5: PoC Generator (Validating Findings)"})

		// Build findings context from Brain
		brainMu.Lock()
		var findingsContext string
		if len(brain.Findings) > 0 {
			findingsContext = "CONFIRMED FINDINGS FROM BRAIN:\n"
			for i, f := range brain.Findings {
				findingsContext += fmt.Sprintf("%d. %s at %s (param: %s)\n", i+1, f.Type, f.URL, f.Parameter)
			}
		} else {
			findingsContext = "No confirmed findings in Brain. Review swarm results for potential issues."
		}
		brainMu.Unlock()

		pocPrompt := o.prompts.BuildPhasePrompt("PoC_GENERATOR", o.prompts.Phases.PocGenerator, flow.Target, userPrompt, "")

		pocInput := findingsContext + "\n\nSWARM RESULTS:\n" + swarmResults

		pocCtx, cancelPoc := context.WithCancel(ctx)
		defer cancelPoc()
		if o.conductor != nil {
			o.conductor.RegisterAgent(pocSubtask.ID, "PoC Generator", flow.Target, cancelPoc)
			defer o.conductor.DeregisterAgent(pocSubtask.ID, StatusComplete)
		}

		pocResult := o.runAgentLoop(pocCtx, flowID, task.ID, pocSubtask.ID, pocPrompt, "Generate PoCs for these findings:\n"+pocInput, &brain, &brainMu)

		// ==========================================
		// PHASE 5.5: VISUAL VALIDATION & OOB POLLING
		// ==========================================
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "👁️ Phase 5.5: Visual Validation & OOB Callback Check"})

		brainMu.Lock()
		xssFindings := make([]*Finding, 0)
		for _, f := range brain.Findings {
			upper := strings.ToUpper(f.Type)
			if upper == "XSS" || upper == "CSTI" || upper == "SSTI" {
				xssFindings = append(xssFindings, f)
			}
		}
		brainMu.Unlock()

		// Visual Validation: Confirm XSS findings with actual browser screenshots
		for _, f := range xssFindings {
			validCtx, cancelValid := context.WithTimeout(ctx, 15*time.Second)
			confirmed, reason, screenshot, err := o.validator.ValidateXSS(validCtx, f.URL, f.Parameter, f.Payload, strings.ToUpper(f.Method) == "POST")
			cancelValid()

			if err != nil {
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
					Content: fmt.Sprintf("⚠️ Visual validation failed for %s at %s: %v", f.Type, f.URL, err)})
				continue
			}

			if confirmed {
				f.Confidence = 1.0
				if f.Evidence == nil {
					f.Evidence = make(map[string]interface{})
				}
				f.Evidence["visual_validation"] = reason
				f.Evidence["screenshot"] = screenshot
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
					Content: fmt.Sprintf("✅ VISUALLY CONFIRMED: %s at %s — %s", f.Type, f.URL, reason)})
			} else {
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
					Content: fmt.Sprintf("❌ Not visually confirmed: %s at %s — %s", f.Type, f.URL, reason)})
			}
		}

		// OOB Polling: Check for blind vulnerability callbacks
		oobInteractions := o.oobManager.GetInteractions(flowID.String())
		if len(oobInteractions) > 0 {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
				Content: fmt.Sprintf("🎯 OOB CONFIRMED: %d blind vulnerabilities received callbacks!", len(oobInteractions))})

			brainMu.Lock()
			for _, interaction := range oobInteractions {
				oobFinding := &Finding{
					Type:       interaction.VulnType,
					URL:        interaction.TargetURL,
					Parameter:  interaction.Parameter,
					Severity:   "critical",
					Confidence: 1.0,
					Evidence: map[string]interface{}{
						"oob_type":     interaction.Type,
						"oob_remote":   interaction.RemoteIP,
						"oob_raw_data": interaction.RawData,
						"oob_token":    interaction.Token,
					},
				}
				brain.Findings = append(brain.Findings, oobFinding)
			}
			brainMu.Unlock()

			pocResult += fmt.Sprintf("\n\n## OOB Confirmed Findings\n%d blind vulnerabilities confirmed via out-of-band callbacks.\n", len(oobInteractions))
		} else if o.oobManager.PendingCount() > 0 {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
				Content: fmt.Sprintf("⏳ %d OOB tokens still pending (callbacks may arrive later).", o.oobManager.PendingCount())})
		}

		// ==========================================
		// PIPELINE: VALIDATION → REPORTING → COMPLETE
		// ==========================================
		// PHASE 5: REPORTING
		// ==========================================
		if err := o.pipeline.Advance("Validation complete", nil); err != nil {
			log.Printf("[pipeline] Advance to REPORTING failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		o.emit(flowID.String(), Event{
			Type:    EventThinking,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: "Generating Final Report...",
		})

		// Advanced Deduplication: Remove redundant findings that share a common root cause
		brainMu.Lock()
		originalCount := len(brain.Findings)
		brain.Findings = DedupFindings(brain.Findings)
		dedupedCount := len(brain.Findings)
		brainMu.Unlock()

		if dedupedCount < originalCount {
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("🧹 Advanced Deduplication: Compressed %d findings into %d unique root causes.", originalCount, dedupedCount),
			})
		}

		// Save this flow's findings to cross-flow memory for future scans
		o.memory.SaveBrainFindings(flow.Target, flowID, brain.Leads, brain.Findings, brain.Exclusions)

		swarmRes := "" // Pull from findings for now
		for _, f := range brain.Findings {
			swarmRes += fmt.Sprintf("- %s: %s (param: %s)\n", f.Type, f.URL, f.Parameter)
		}

		finalReport := o.reporter.GenerateReport(
			flow.Target,
			flowID,
			time.Since(task.CreatedAt),
			brain.PivotContext,
			brain.Findings,
			brain.Leads,
			brain.Exclusions,
			swarmRes,
			pocResult,
		)

		o.queries.UpdateTaskStatus(task.ID, models.TaskStatusDone, finalReport)
		o.queries.UpdateFlowStatus(flowID, models.FlowStatusCompleted)

		// Final transition: REPORTING → COMPLETE
		if err := o.pipeline.Advance("Report generated", map[string]interface{}{
			"total_findings": len(brain.Findings),
			"total_leads":    len(brain.Leads),
			"total_excluded": len(brain.Exclusions),
			"duration_sec":   o.pipeline.TotalDuration().Seconds(),
		}); err != nil {
			log.Printf("[pipeline] Advance to COMPLETE failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		// Break the iterative loop successfully
		o.emit(flowID.String(), Event{
			Type:    EventComplete,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: "Vulnerability Assessment Complete",
		})
		break
	} // END FOR LOOP

	return nil
}

func (o *Orchestrator) runAgentLoop(ctx context.Context, flowID uuid.UUID, taskID uuid.UUID, subtaskID uuid.UUID, systemPrompt string, userPrompt string, brain *Brain, brainMu *sync.Mutex) string {
	if o.queries != nil {
		o.queries.UpdateSubTaskStatus(subtaskID, models.SubTaskStatusRunning)
	}

	successCount := 0
	var chatMsgs []models.ChatMessage
	chatMsgs = append(chatMsgs, models.ChatMessage{Role: "user", Content: userPrompt})

	// Feature: Redirect Tracking (302 Intelligence)
	redirectTracker := NewRedirectTracker()

	// Feature: Forced Reflection on Repeated Failure
	consecutiveFailures := 0
	const failureReflectionThreshold = 3
	const failureTerminateThreshold = 5

	var lastResult string
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			return "Cancelled"
		default:
		}

		brainMu.Lock()
		bJSON, _ := json.Marshal(brain)

		// Inject Tech Context (Prime Directive) if available
		effectiveSystemPrompt := systemPrompt
		if brain.Tech != nil {
			techCtx := GenerateContextPrompt(brain.Tech)
			// If it's a swarm specialist, use a more targeted context
			lowerPrompt := strings.ToLower(systemPrompt)
			if strings.Contains(lowerPrompt, "specialist") || strings.Contains(lowerPrompt, "hunt for") {
				switch {
				case strings.Contains(lowerPrompt, "xss"):
					techCtx = GenerateXSSContext(brain.Tech)
				case strings.Contains(lowerPrompt, "sqli") || strings.Contains(lowerPrompt, "sql injection"):
					techCtx = GenerateSQLiContext(brain.Tech)
				case strings.Contains(lowerPrompt, "ssrf"):
					techCtx = GenerateSSRFContext(brain.Tech)
				case strings.Contains(lowerPrompt, "rce"):
					techCtx = GenerateRCEContext(brain.Tech)
				case strings.Contains(lowerPrompt, "lfi") || strings.Contains(lowerPrompt, "path traversal"):
					techCtx = GenerateLFIContext(brain.Tech)
				case strings.Contains(lowerPrompt, "csti") || strings.Contains(lowerPrompt, "ssti") || strings.Contains(lowerPrompt, "template injection"):
					techCtx = GenerateCSTIContext(brain.Tech)
				}
			}
			effectiveSystemPrompt = techCtx + "\n\n" + systemPrompt
		}

		// Feature: Inject Auth Context if credentials/cookies are available
		if brain.Auth != nil {
			var authDirective strings.Builder
			authDirective.WriteString("\n\n🔑 AUTHENTICATION CONTEXT (use these in all requests):\n")
			if len(brain.Auth.Cookies) > 0 {
				authDirective.WriteString("Session Cookies: ")
				for k, v := range brain.Auth.Cookies {
					authDirective.WriteString(fmt.Sprintf("%s=%s; ", k, v))
				}
				authDirective.WriteString("\nAlways include these cookies with -b or --cookie flags in curl commands.\n")
			}
			if len(brain.Auth.Credentials) > 0 {
				authDirective.WriteString("Discovered Credentials:\n")
				for user, pass := range brain.Auth.Credentials {
					authDirective.WriteString(fmt.Sprintf("  - %s : %s\n", user, pass))
				}
				authDirective.WriteString("Use these to authenticate if you encounter login pages.\n")
			}
			if brain.Auth.LoginURL != "" {
				authDirective.WriteString(fmt.Sprintf("Login Page: %s\n", brain.Auth.LoginURL))
			}
			effectiveSystemPrompt += authDirective.String()
		}
		brainMu.Unlock()

		// Feature: Context Compression — summarize old messages to prevent token overflow
		if shouldCompress(chatMsgs) {
			log.Printf("[compress] Triggering conversation compression (%d messages, ~%d tokens)", len(chatMsgs), estimateTokens(chatMsgs))
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  taskID.String(),
				Content: fmt.Sprintf("📊 Compressing conversation history (%d messages → summary + %d recent)", len(chatMsgs), CompressKeepRecent),
			})
			chatMsgs = o.compressConversation(ctx, chatMsgs, CompressKeepRecent)
		}

		currentMsgs := append([]models.ChatMessage{
			{Role: "system", Content: effectiveSystemPrompt},
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
					// 1. Scope Check
					inScope := true
					reason := ""
					if o.scope != nil {
						inScope, reason = o.scope.IsCommandInScope(tc.Arguments)
					}

					if !inScope {
						res = reason
					} else {
						// 2. Execute with Self-Healing Resilience
						res, _ = ExecuteWithHealing(ctx, tc.Name, func(args json.RawMessage) (string, error) {
							// 3. Adaptive Rate Flag Injection
							finalArgs := args
							if tc.Name == "execute_command" {
								var params map[string]interface{}
								json.Unmarshal(args, &params)
								if cmd, ok := params["command"].(string); ok {
									params["command"] = o.rateLimiter.InjectRateFlags(cmd)
									finalArgs, _ = json.Marshal(params)
								}
							}

							output, err := tool.Execute(ctx, finalArgs)

							// 4. WAF/Throttle Detection & Strategy Shift (Phase 14)
							if o.isWAFBlocked(output) {
								o.emit(flowID.String(), Event{
									Type:    EventMessage,
									FlowID:  flowID.String(),
									TaskID:  taskID.String(),
									Content: "🚨 [WAF BLOCK] Evasion strategy triggered.",
								})
								strategy := o.strategist.SuggestedEncoding(tc.Name, output)
								o.emit(flowID.String(), Event{
									Type:    EventMessage,
									FlowID:  flowID.String(),
									TaskID:  taskID.String(),
									Content: fmt.Sprintf("🛡️ Strategist suggesting shift to: %s", strategy),
								})
								o.rateLimiter.SlowDown()
							} else if o.rateLimiter.IsWAFDetected() {
								o.rateLimiter.SpeedUp()
							}

							return output, err
						}, json.RawMessage(tc.Arguments), func(msg string) {
							o.emit(flowID.String(), Event{
								Type:    EventMessage,
								FlowID:  flowID.String(),
								TaskID:  taskID.String(),
								Content: msg,
							})
						})
					}
				}

				// Restore Action Persistence
				if o.queries != nil {
					o.queries.CreateAction(subtaskID, models.ActionTypeCommand, tc.Arguments, res, "success")
				}

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

				// ============================================
				// Feature: Redirect Tracking (302 Intelligence)
				// ============================================
				if tc.Name == "execute_command" {
					if insight := redirectTracker.Analyze(res); insight != nil && insight.ShouldPivot {
						// Inject auth wall alert into the conversation
						chatMsgs = append(chatMsgs, models.ChatMessage{
							Role:    "user",
							Content: insight.Message,
						})
						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: fmt.Sprintf("🔒 [AUTH WALL] %d redirects to %s detected. Pivoting strategy.", insight.RedirectCount, insight.LoginURL),
						})

						// Map login page as high-priority target in Brain
						brainMu.Lock()
						brain.Leads = append(brain.Leads, fmt.Sprintf("[AUTH-TARGET] Login page at %s — try auth bypass, default credentials, or credential stuffing", insight.LoginURL))
						if brain.Auth == nil {
							brain.Auth = &AuthState{}
						}
						if brain.Auth.LoginURL == "" {
							brain.Auth.LoginURL = insight.LoginURL
						}
						brainMu.Unlock()
					}

					// Detect credentials in tool output (backup configs, env files, etc.)
					lowerOutput := strings.ToLower(res)
					hasCredentialSignals := strings.Contains(lowerOutput, "password") ||
						strings.Contains(lowerOutput, "db_password") ||
						strings.Contains(lowerOutput, "api_key") ||
						strings.Contains(lowerOutput, "secret_key") ||
						strings.Contains(lowerOutput, "phpsessid") ||
						strings.Contains(lowerOutput, "set-cookie")
					if hasCredentialSignals {
						brainMu.Lock()
						if brain.Auth == nil {
							brain.Auth = &AuthState{
								Cookies:     make(map[string]string),
								Credentials: make(map[string]string),
							}
						}
						// Emit credential discovery pivot
						o.bus.Emit(EventPivotDiscovered, fmt.Sprintf("Potential credentials detected in tool output for %s", tc.Name))
						brainMu.Unlock()
					}
				}

				// ============================================
				// Feature: Forced Reflection on Repeated Failure
				// ============================================
				isFailure := isToolOutputFailure(res)
				if isFailure {
					consecutiveFailures++

					if consecutiveFailures >= failureTerminateThreshold {
						// Hard stop — too many failures, agent is stalled
						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: fmt.Sprintf("🛑 [STALLED] %d consecutive failures — terminating this agent to save resources.", consecutiveFailures),
						})
						lastResult = fmt.Sprintf("Terminated: %d consecutive failures detected. Agent is stalled on an unproductive approach.", consecutiveFailures)
						goto done
					}

					if consecutiveFailures >= failureReflectionThreshold {
						reflectionMsg := fmt.Sprintf(
							"⚠️ FORCED REFLECTION: You've had %d consecutive failures. "+
								"STOP your current approach immediately.\n\n"+
								"REQUIRED ACTIONS:\n"+
								"1. Analyze WHY your last %d attempts failed\n"+
								"2. Identify the ROOT CAUSE (wrong endpoint? auth required? wrong parameter?)\n"+
								"3. Choose a FUNDAMENTALLY DIFFERENT strategy\n"+
								"4. Do NOT retry the same approach\n\n"+
								"If you're hitting 302 redirects, the target requires authentication. "+
								"Try: default credentials, auth bypass, or explore unauthenticated endpoints instead.",
							consecutiveFailures, consecutiveFailures,
						)
						chatMsgs = append(chatMsgs, models.ChatMessage{
							Role:    "user",
							Content: reflectionMsg,
						})
						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: fmt.Sprintf("🔄 [FORCED REFLECTION] %d consecutive failures — injecting strategy pivot.", consecutiveFailures),
						})
					}
				} else {
					// Reset on success
					consecutiveFailures = 0
				}

				if tc.Name == "complete_task" {
					// FEATURE: Reflector Agent Validation (VETO Power)
					// Before unconditionally accepting success, have the Reflector analyze the logs to verify proof.
					reflector := NewReflector(o.llmProvider)
					SystemPromptForReflector := fmt.Sprintf("Goal: %s\nTarget: %s", userPrompt, brain.Tech)
					isValid, vetoReason := reflector.ValidateFinding(ctx, SystemPromptForReflector, chatMsgs, res)

					if !isValid {
						// The Reflector VETOED the finding. Do not terminate.
						vetoMsg := fmt.Sprintf("🚨 REFLECTOR VETO: Your reported finding was REJECTED by the auditor.\nREASON: %s\n\nYou MUST continue working to find actual proof, or try a different approach. Do not call complete_task until you have concrete proof in the logs.", vetoReason)

						chatMsgs = append(chatMsgs, models.ChatMessage{
							Role:    "user",
							Content: vetoMsg,
						})

						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: "🚨 [REFLECTOR VETO] Finding rejected. " + vetoReason,
						})

						// Continue the loop, forcing the agent to try again
						continue
					}

					// Reflector approved, or it was a valid finding.
					o.emit(flowID.String(), Event{
						Type:    EventMessage,
						FlowID:  flowID.String(),
						TaskID:  taskID.String(),
						Content: "✅ [REFLECTOR APPROVED] Finding validated against execution logs.",
					})

					lastResult = res
					goto done
				}

				// Victory Hierarchy Check: Stop if we've achieved high impact
				if tc.Name == "execute_command" {
					lowerRes := strings.ToLower(res)
					if strings.Contains(lowerRes, "success") || strings.Contains(lowerRes, "pwned") || strings.Contains(lowerRes, "vulnerable") {
						successCount++
						evidence := map[string]interface{}{"output": res}
						stop, reason := ShouldStopTesting(res, evidence, successCount)
						if stop {
							o.emit(flowID.String(), Event{
								Type:    EventComplete,
								FlowID:  flowID.String(),
								TaskID:  taskID.String(),
								Content: "🏆 VICTORY HIERARCHY TRIGGERED: " + reason,
							})
							lastResult = "VICTORY HIERARCHY: " + reason + "\n\n" + res
							goto done
						}
					}
				}
			}
		} else {
			chatMsgs = append(chatMsgs, models.ChatMessage{Role: "user", Content: "Continue. Use tools or complete_task."})
		}
	}
	lastResult = "Max iterations reached"

done:
	if o.queries != nil {
		o.queries.UpdateSubTaskStatus(subtaskID, models.SubTaskStatusCompleted)
	}
	return lastResult
}

func (o *Orchestrator) updateTechStackFromNote(ts *TechStack, note string) {
	noteLower := strings.ToLower(note)
	// Simple keyword mapping for extraction
	if strings.Contains(noteLower, "php") {
		ts.Lang = "PHP"
	} else if strings.Contains(noteLower, "python") || strings.Contains(noteLower, "django") || strings.Contains(noteLower, "flask") {
		ts.Lang = "Python"
	} else if strings.Contains(noteLower, "java") || strings.Contains(noteLower, "spring") {
		ts.Lang = "Java"
	} else if strings.Contains(noteLower, "node") || strings.Contains(noteLower, "express") || strings.Contains(noteLower, "next.js") {
		ts.Lang = "Node.js"
	}

	if strings.Contains(noteLower, "mysql") || strings.Contains(noteLower, "mariadb") {
		ts.DB = "MySQL"
	} else if strings.Contains(noteLower, "postgres") || strings.Contains(noteLower, "postgresql") {
		ts.DB = "PostgreSQL"
	} else if strings.Contains(noteLower, "mssql") || strings.Contains(noteLower, "sql server") {
		ts.DB = "MSSQL"
	} else if strings.Contains(noteLower, "sqlite") {
		ts.DB = "SQLite"
	}

	if strings.Contains(noteLower, "apache") {
		ts.Server = "Apache"
	} else if strings.Contains(noteLower, "nginx") {
		ts.Server = "Nginx"
	} else if strings.Contains(noteLower, "iis") {
		ts.Server = "IIS"
	}
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

func (o *Orchestrator) isWAFBlocked(output string) bool {
	lower := strings.ToLower(output)
	indicators := []string{
		"403 forbidden",
		"429 too many requests",
		"access denied",
		"captcha",
		"cloudflare",
		"akamai",
		"waf",
		"block",
		"pardon our interruption",
	}
	for _, ind := range indicators {
		if strings.Contains(strings.ToLower(lower), ind) {
			return true
		}
	}
	return false
}

// emitPipelineEvent sends the current pipeline state to the frontend
func (o *Orchestrator) emitPipelineEvent(flowID, taskID string) {
	if o.pipeline == nil {
		return
	}
	o.emit(flowID, Event{
		Type:     EventMessage,
		FlowID:   flowID,
		TaskID:   taskID,
		Content:  fmt.Sprintf("⚡ Pipeline Phase: %s", o.pipeline.Current()),
		Metadata: o.pipeline.ToMap(),
	})
	// Also emit on internal bus for Conductor/WebSocket
	o.bus.Emit(EventTypeInternal("pipeline_phase_change"), o.pipeline.ToMap())
}

// emitQueueStats sends current queue statistics to the frontend
func (o *Orchestrator) emitQueueStats(flowID, taskID string) {
	stats := o.queueMgr.GetAllStats()
	queueData := make(map[string]interface{})
	for name, s := range stats {
		queueData[name] = map[string]interface{}{
			"enqueued":   s.Enqueued,
			"dequeued":   s.Dequeued,
			"rejected":   s.Rejected,
			"avg_lat_ms": s.AvgLatMs,
			"peak_depth": s.PeakDepth,
		}
	}
	o.emit(flowID, Event{
		Type:     EventMessage,
		FlowID:   flowID,
		TaskID:   taskID,
		Content:  "📊 Queue Stats Updated",
		Metadata: queueData,
	})
	o.bus.Emit(EventTypeInternal("queue_stats"), queueData)
}

// normalizeSpecialistName converts dispatch names to queue keys
func normalizeSpecialistName(name string) string {
	nameMap := map[string]string{
		"XSS":                 "xss",
		"xss":                 "xss",
		"Reflected XSS":       "xss",
		"Stored XSS":          "xss",
		"DOM XSS":             "xss",
		"SQLi":                "sqli",
		"sqli":                "sqli",
		"SQL Injection":       "sqli",
		"SSRF":                "ssrf",
		"ssrf":                "ssrf",
		"LFI":                 "lfi",
		"lfi":                 "lfi",
		"Path Traversal":      "lfi",
		"RCE":                 "rce",
		"rce":                 "rce",
		"Command Injection":   "rce",
		"XXE":                 "xxe",
		"xxe":                 "xxe",
		"Open Redirect":       "openredirect",
		"IDOR":                "idor",
		"idor":                "idor",
		"CSTI":                "csti",
		"SSTI":                "csti",
		"Template Injection":  "csti",
		"Header Injection":    "header_injection",
		"CRLF":                "header_injection",
		"Prototype Pollution": "protopollution",
		"protopollution":      "protopollution",
		"JWT":                 "jwt",
		"jwt":                 "jwt",
		"JWT Analysis":        "jwt",
		"File Upload":         "fileupload",
		"fileupload":          "fileupload",
		"Upload":              "fileupload",
		"API Security":        "apisecurity",
		"API":                 "apisecurity",
		"Asset Discovery":     "assetdiscovery",
		"Recon":               "assetdiscovery",
		"Auth Discovery":      "authdiscovery",
		"Authentication":      "authdiscovery",
		"Chain Discovery":     "chaindiscovery",
		"Attack Chain":        "chaindiscovery",
		"Consolidation":       "consolidation",
		"Thinking":            "consolidation",
		"DASTySAST":           "dastysast",
		"DAST":                "dastysast",
		"GoSpider":            "gospider",
		"Crawler":             "gospider",
		"Mass Assignment":     "massassignment",
		"Nuclei":              "nuclei",
		"nuclei":              "nuclei",
		"Reporting":           "reporting",
		"Report":              "reporting",
		"SQLMap":              "sqlmap",
		"sqlmap":              "sqlmap",
		"Validation":          "validation",
		"Verify":              "validation",
		"Cloud Hunter":        "cloudhunter",
		"cloudhunter":         "cloudhunter",
		"Resource Hunter":     "resourcehunter",
		"resourcehunter":      "resourcehunter",
		"WAF Evasion":         "wafevasion",
		"wafevasion":          "wafevasion",
		"Business Logic":      "businesslogic",
		"businesslogic":       "businesslogic",
		"URLMaster":           "urlmaster",
		"urlmaster":           "urlmaster",
		"Visual Crawler":      "visualcrawler",
		"visualcrawler":       "visualcrawler",
	}
	if q, ok := nameMap[name]; ok {
		return q
	}
	return "xss" // Fallback
}

// isToolOutputFailure detects failure patterns in tool execution output.
// Returns true if the output indicates a failed/unproductive command execution.
func isToolOutputFailure(output string) bool {
	if output == "" || output == "null" || output == "{}" {
		return true
	}

	lower := strings.ToLower(output)

	// 302/301 redirects to login pages (auth wall)
	if (strings.Contains(lower, "302") || strings.Contains(lower, "301")) &&
		(strings.Contains(lower, "login") || strings.Contains(lower, "signin") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "session")) {
		return true
	}

	// HTTP error codes
	for _, code := range []string{"403 forbidden", "404 not found", "500 internal server error",
		"502 bad gateway", "503 service unavailable"} {
		if strings.Contains(lower, code) {
			return true
		}
	}

	// Bash/shell syntax errors
	bashErrors := []string{
		"unexpected eof",
		"syntax error",
		"command not found",
		"no such file or directory",
		"permission denied",
	}
	for _, pattern := range bashErrors {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Timeout indicators
	if strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout") {
		return true
	}

	// Tool errors
	if strings.HasPrefix(output, "Error:") || strings.HasPrefix(output, "Tool not found:") {
		return true
	}

	return false
}

// ---------------------------------------------------------------------------
// Causal Evidence Graph Helpers
// ---------------------------------------------------------------------------

// AddCausalNode safely adds a new node to the Brain's CausalGraph
func (o *Orchestrator) AddCausalNode(brain *Brain, brainMu *sync.Mutex, node models.CausalNode) {
	brainMu.Lock()
	defer brainMu.Unlock()

	if brain.CausalGraph == nil {
		brain.CausalGraph = &models.CausalGraph{
			Nodes: make(map[string]*models.CausalNode),
			Edges: []models.CausalEdge{},
		}
	}

	// Create a copy to store in the map
	n := node
	brain.CausalGraph.Nodes[node.ID] = &n
}

// AddCausalEdge safely links two nodes in the Brain's CausalGraph
func (o *Orchestrator) AddCausalEdge(brain *Brain, brainMu *sync.Mutex, sourceID, targetID, label string) {
	brainMu.Lock()
	defer brainMu.Unlock()

	if brain.CausalGraph == nil {
		brain.CausalGraph = &models.CausalGraph{
			Nodes: make(map[string]*models.CausalNode),
			Edges: []models.CausalEdge{},
		}
	}

	brain.CausalGraph.Edges = append(brain.CausalGraph.Edges, models.CausalEdge{
		SourceID: sourceID,
		TargetID: targetID,
		Label:    label,
	})
}
