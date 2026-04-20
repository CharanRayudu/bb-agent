package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/agent/schema"
	"github.com/bb-agent/mirage/internal/knowledge"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/agents/apisecurity"
	"github.com/bb-agent/mirage/internal/agents/assetdiscovery"
	"github.com/bb-agent/mirage/internal/agents/authdiscovery"
	"github.com/bb-agent/mirage/internal/agents/blindoracle"
	"github.com/bb-agent/mirage/internal/agents/businesslogic"
	"github.com/bb-agent/mirage/internal/agents/cachepoisoning"
	"github.com/bb-agent/mirage/internal/agents/chaindiscovery"
	"github.com/bb-agent/mirage/internal/agents/cloudhunter"
	"github.com/bb-agent/mirage/internal/agents/consolidation"
	"github.com/bb-agent/mirage/internal/agents/cors"
	"github.com/bb-agent/mirage/internal/agents/csti"
	"github.com/bb-agent/mirage/internal/agents/dastysast"
	"github.com/bb-agent/mirage/internal/agents/deserialization"
	"github.com/bb-agent/mirage/internal/agents/fileupload"
	"github.com/bb-agent/mirage/internal/agents/gospider"
	"github.com/bb-agent/mirage/internal/agents/headerinjection"
	"github.com/bb-agent/mirage/internal/agents/idor"
	"github.com/bb-agent/mirage/internal/agents/jwt"
	k8sagent "github.com/bb-agent/mirage/internal/agents/k8s"
	"github.com/bb-agent/mirage/internal/agents/lfi"
	"github.com/bb-agent/mirage/internal/agents/log4shell"
	"github.com/bb-agent/mirage/internal/agents/massassignment"
	graphqlagent "github.com/bb-agent/mirage/internal/agents/graphql"
	"github.com/bb-agent/mirage/internal/agents/hostheader"
	"github.com/bb-agent/mirage/internal/agents/nuclei"
	"github.com/bb-agent/mirage/internal/agents/oauth"
	"github.com/bb-agent/mirage/internal/agents/openredirect"
	"github.com/bb-agent/mirage/internal/agents/postexploit"
	"github.com/bb-agent/mirage/internal/agents/protopollution"
	"github.com/bb-agent/mirage/internal/agents/rce"
	reportingagent "github.com/bb-agent/mirage/internal/agents/reporting"
	"github.com/bb-agent/mirage/internal/agents/resourcehunter"
	"github.com/bb-agent/mirage/internal/agents/s3enum"
	"github.com/bb-agent/mirage/internal/agents/saml"
	"github.com/bb-agent/mirage/internal/agents/secondorder"
	"github.com/bb-agent/mirage/internal/agents/racecondition"
	"github.com/bb-agent/mirage/internal/agents/smuggling"
	"github.com/bb-agent/mirage/internal/agents/sqli"
	"github.com/bb-agent/mirage/internal/agents/sqlmap"
	"github.com/bb-agent/mirage/internal/agents/ssrf"
	"github.com/bb-agent/mirage/internal/agents/ssti"
	"github.com/bb-agent/mirage/internal/agents/urlmaster"
	"github.com/bb-agent/mirage/internal/agents/validation"
	"github.com/bb-agent/mirage/internal/agents/visualcrawler"
	"github.com/bb-agent/mirage/internal/agents/wafevasion"
	"github.com/bb-agent/mirage/internal/agents/websocket"
	"github.com/bb-agent/mirage/internal/agents/xss"
	"github.com/bb-agent/mirage/internal/agents/xxe"
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
	Notes       []string          `json:"notes,omitempty"`       // Freeform auth observations to preserve across specialists
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
	// Mythos: refined attack hypotheses — included in next planner iteration for adaptive prioritization
	Hypotheses []AttackHypothesis `json:"hypotheses,omitempty"`
}

// SwarmAgentSpec is a richer agent dispatch format from the Planner
type SwarmAgentSpec struct {
	Type         string `json:"type"`                    // e.g. "SQLi", "XSS", "Code Review"
	Target       string `json:"target,omitempty"`        // specific endpoint/param
	Context      string `json:"context,omitempty"`       // what the planner observed
	Hypothesis   string `json:"hypothesis,omitempty"`    // focused attack-path hypothesis
	Proof        string `json:"proof,omitempty"`         // proof required for promotion
	RequiresAuth bool   `json:"requires_auth,omitempty"` // whether auth continuity matters
	AuthContext  string `json:"auth_context,omitempty"`  // auth notes/cookies/tokens to preserve
	Priority     string `json:"priority,omitempty"`      // "critical", "high", "medium", "low"
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

	// Mythos: Pre-dispatch hypothesis reasoning engine
	hypothesisEngine *HypothesisEngine

	// Mythos: Cross-session knowledge graph for payload effectiveness learning
	knowledgeGraph knowledge.Graph

	// Mythos: Feedback-driven adaptive payload engine
	payloadEngine *PayloadEngine

	// Mythos: Active WAF fingerprint per target (shared across all agents)
	wafResult   WAFResult
	wafResultMu sync.RWMutex

	// Phase 14: The Phoenix Pivot & WAF Strategist
	strategist *WAFStrategist

	// Phase 15: The Mirage Singularity (Performance & Precision)
	workers map[string]*Worker

	// Pause/Resume support
	pausedFlows map[uuid.UUID]context.CancelFunc
	pauseMu     sync.RWMutex
}

func buildSpecialists(provider llm.Provider) map[string]Specialist {
	// Build an LLMMutator so the WAF evasion specialist can use LLM-driven mutation.
	// model is informational; the provider already carries the configured model.
	var wafAgent Specialist
	if provider != nil {
		mutator := base.NewLLMMutator(provider, "")
		wafAgent = wafevasion.NewWithMutator(mutator)
	} else {
		wafAgent = wafevasion.New()
	}

	return map[string]Specialist{
		"apisecurity":       apisecurity.New(),
		"assetdiscovery":    assetdiscovery.New(),
		"authdiscovery":     authdiscovery.New(),
		"blindoracle":       blindoracle.New(),
		"businesslogic":     businesslogic.New(),
		"cachepoisoning":    cachepoisoning.New(),
		"chaindiscovery":    chaindiscovery.New(),
		"cloudhunter":       cloudhunter.New(),
		"consolidation":     consolidation.New(),
		"cors":              cors.New(),
		"csti":              csti.New(),
		"dastysast":         dastysast.New(),
		"deserialization":   deserialization.New(),
		"fileupload":        fileupload.New(),
		"gospider":          gospider.New(),
		"graphql":           graphqlagent.New(),
		"header_injection":  headerinjection.New(),
		"hostheader":        hostheader.New(),
		"idor":              idor.New(),
		"jwt":               jwt.New(),
		"k8s":               k8sagent.New(),
		"lfi":               lfi.New(),
		"log4shell":         log4shell.New(),
		"massassignment":    massassignment.New(),
		"nuclei":            nuclei.New(),
		"oauth":             oauth.New(),
		"openredirect":      openredirect.New(),
		"protopollution":    protopollution.New(),
		"rce":               rce.New(),
		"reporting":         reportingagent.New(),
		"resourcehunter":    resourcehunter.New(),
		"s3enum":            s3enum.New(),
		"racecondition":     racecondition.New(),
		"saml":              saml.New(),
		"secondorder":       secondorder.New(),
		"smuggling":         smuggling.New(),
		"sqli":              sqli.New(),
		"sqlmap":            sqlmap.New(),
		"ssrf":              ssrf.New(),
		"ssti":              ssti.New(),
		"urlmaster":         urlmaster.New(),
		"validation":        validation.New(),
		"visualcrawler":     visualcrawler.New(),
		"wafevasion":        wafAgent,
		"websocket":         websocket.New(),
		"xss":               xss.New(),
		"xxe":               xxe.New(),
	}
}

func normalizePriority(priority string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(priority))
	default:
		return "medium"
	}
}

func parseBaseTarget(target string) *url.URL {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil
	}
	return parsed
}

func resolveDispatchTarget(baseTarget, candidate string) string {
	candidate = strings.Trim(strings.TrimSpace(candidate), `"'`)
	if candidate == "" {
		if base := parseBaseTarget(baseTarget); base != nil {
			return base.String()
		}
		return strings.TrimSpace(baseTarget)
	}

	if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
		return candidate
	}

	base := parseBaseTarget(baseTarget)
	if base == nil {
		return candidate
	}

	if strings.HasPrefix(candidate, "/") {
		if ref, err := url.Parse(candidate); err == nil {
			return base.ResolveReference(ref).String()
		}
	}

	if !strings.Contains(candidate, " ") && (strings.ContainsAny(candidate, "/?#=&") || strings.Contains(candidate, ".")) {
		if ref, err := url.Parse(candidate); err == nil && ref.Scheme == "" && ref.Host == "" {
			return base.ResolveReference(ref).String()
		}
	}

	return base.String()
}

func extractTargetHint(context string) string {
	for _, token := range strings.Fields(context) {
		cleaned := strings.Trim(token, "\"'()[]{}<>,")
		if strings.HasPrefix(cleaned, "http://") || strings.HasPrefix(cleaned, "https://") || strings.HasPrefix(cleaned, "/") {
			return cleaned
		}
	}
	return ""
}

func detectDispatchMethod(context string) string {
	lower := strings.ToLower(context)
	switch {
	case strings.Contains(lower, " put "):
		return "PUT"
	case strings.Contains(lower, " patch "):
		return "PATCH"
	case strings.Contains(lower, " delete "):
		return "DELETE"
	case strings.Contains(lower, " post "):
		return "POST"
	default:
		return "GET"
	}
}

func buildWorkerPayload(baseTarget string, spec SwarmAgentSpec, contextOverride string, auth *AuthState) map[string]interface{} {
	spec = enrichSwarmAgentSpec(baseTarget, spec, auth)
	queueName := normalizeSpecialistName(spec.Type)
	effectiveContext := strings.TrimSpace(contextOverride)
	if effectiveContext == "" {
		effectiveContext = strings.TrimSpace(spec.Context)
	}
	effectiveContext = composeSpecialistContext(spec, effectiveContext)

	targetURL := resolveDispatchTarget(baseTarget, spec.Target)
	proofRequirement := strings.TrimSpace(spec.Proof)
	graphNodeID := attackGraphNodeID("hypothesis", dispatchFingerprint(spec, baseTarget))

	payload := map[string]interface{}{
		"type":              spec.Type,
		"target":            targetURL,
		"target_url":        targetURL,
		"url":               targetURL,
		"context":           effectiveContext,
		"priority":          normalizePriority(spec.Priority),
		"method":            detectDispatchMethod(" " + effectiveContext + " "),
		"hypothesis":        spec.Hypothesis,
		"proof_requirement": proofRequirement,
		"requires_auth":     spec.RequiresAuth,
		"auth_context":      spec.AuthContext,
		"attack_graph_node": graphNodeID,
	}
	if authDetails := authPayload(auth); len(authDetails) > 0 {
		payload["auth"] = authDetails
	}

	switch queueName {
	case "cloudhunter":
		payload["infrastructure"] = effectiveContext
	case "wafevasion":
		payload["blocked_payload"] = ""
		payload["vuln_type"] = spec.Type
		payload["waf"] = ""
	}

	return payload
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
	// Phase 16: New specialist agents
	qm.Register("saml", 50, 3.0)
	qm.Register("s3enum", 50, 5.0)
	qm.Register("secondorder", 50, 3.0)
	// Agents added without queue registration — fixed
	qm.Register("blindoracle", 30, 2.0)
	qm.Register("cachepoisoning", 50, 3.0)
	qm.Register("cors", 100, 5.0)
	qm.Register("deserialization", 30, 2.0)
	qm.Register("graphql", 50, 5.0)
	qm.Register("hostheader", 50, 5.0)
	qm.Register("k8s", 30, 2.0)
	qm.Register("log4shell", 30, 2.0)
	qm.Register("oauth", 50, 3.0)
	qm.Register("postexploit", 20, 1.0)
	qm.Register("racecondition", 30, 2.0)
	qm.Register("smuggling", 30, 2.0)
	qm.Register("ssti", 50, 3.0)
	qm.Register("websocket", 30, 2.0)

	o := &Orchestrator{
		llmProvider:      provider,
		toolRegistry:     registry,
		onEvent:          func(e Event) {}, // no-op default
		prompts:          prompts,
		bus:              NewEventBus(),
		queueMgr:         qm,
		memory:           NewMemory(db),
		rateLimiter:      NewAdaptiveRateLimiter(20.0), // Start with 20 req/s
		reporter:         NewReportGenerator(),
		oobManager:       NewOOBManager(""), // Default Interactsh server
		validator:        base.NewVisualValidator(),
		strategist:       NewWAFStrategist(),
		workers:          make(map[string]*Worker),
		pausedFlows:      make(map[uuid.UUID]context.CancelFunc),
		hypothesisEngine: NewHypothesisEngine(provider, ""),
		knowledgeGraph:   knowledge.NewInMemoryGraph(),
		payloadEngine:    NewPayloadEngine(provider),
	}

	if db != nil {
		o.queries = database.NewQueries(db)
	}

	// Register brain-integrated tools
	o.toolRegistry.AddPayloadMutationTool(provider)
	o.toolRegistry.AddVisualCrawlTool(func(ctx context.Context, url string) (string, error) {
		res, err := base.RunCrawl(ctx, url, base.DefaultBrowserOptions())
		if err != nil {
			if base.IsBrowserUnavailableError(err) {
				return "Browser automation disabled for this run; skipping visual crawl.", nil
			}
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

	// Initialize workers only for specialist implementations that exist today.
	for specialistID, specialist := range buildSpecialists(provider) {
		q := o.queueMgr.Get(specialistID)
		if q == nil {
			continue
		}

		o.workers[specialistID] = NewWorker(specialist, q, 5, func(f *Finding) {
			o.bus.Emit(EventFindingDiscovered, cloneFinding(f))
		}, o)
	}

	// Start the in-process OOB callback server for blind injection detection.
	// Uses background context so it lives for the entire process lifetime.
	if err := GlobalOOBServer.Start(context.Background()); err != nil {
		log.Printf("warn: OOB server failed to start: %v", err)
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

// SetKnowledgeGraph replaces the orchestrator's knowledge graph with a shared instance.
func (o *Orchestrator) SetKnowledgeGraph(g knowledge.Graph) {
	o.knowledgeGraph = g
}

// GetKnowledgeGraph returns the orchestrator's knowledge graph.
func (o *Orchestrator) GetKnowledgeGraph() knowledge.Graph {
	return o.knowledgeGraph
}

// PauseFlow cancels the running context for the given flow and marks it as paused.
// The cancel function must have been registered via RegisterFlowCancel before calling this.
func (o *Orchestrator) PauseFlow(flowID uuid.UUID) error {
	o.pauseMu.Lock()
	defer o.pauseMu.Unlock()

	cancel, ok := o.pausedFlows[flowID]
	if !ok {
		return fmt.Errorf("flow %s is not active or already paused", flowID)
	}
	cancel()
	// Keep the entry so ResumeFlow knows about it until a fresh cancel is registered.
	delete(o.pausedFlows, flowID)

	if o.queries != nil {
		o.queries.UpdateFlowStatus(flowID, models.FlowStatusPaused)
	}
	return nil
}

// ResumeFlow restarts a paused flow by launching a new scan goroutine.
// The caller is responsible for wiring the new cancel func back via RegisterFlowCancel.
func (o *Orchestrator) ResumeFlow(flowID uuid.UUID, target string) error {
	if o.queries == nil {
		return fmt.Errorf("queries not initialised")
	}

	flow, err := o.queries.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("flow %s not found: %w", flowID, err)
	}
	if flow.Status != models.FlowStatusPaused {
		return fmt.Errorf("flow %s is not paused (status: %s)", flowID, flow.Status)
	}

	if err := o.queries.UpdateFlowStatus(flowID, models.FlowStatusActive); err != nil {
		return fmt.Errorf("failed to update flow status: %w", err)
	}
	return nil
}

// RegisterFlowCancel stores a cancel function so PauseFlow can use it.
func (o *Orchestrator) RegisterFlowCancel(flowID uuid.UUID, cancel context.CancelFunc) {
	o.pauseMu.Lock()
	defer o.pauseMu.Unlock()
	o.pausedFlows[flowID] = cancel
}

// UnregisterFlowCancel removes the cancel function when a flow ends naturally.
func (o *Orchestrator) UnregisterFlowCancel(flowID uuid.UUID) {
	o.pauseMu.Lock()
	defer o.pauseMu.Unlock()
	delete(o.pausedFlows, flowID)
}

// RunFlow executes a complete penetration testing flow using concurrent agents
func (o *Orchestrator) RunFlow(ctx context.Context, flowID uuid.UUID, userPrompt string) error {
	flow, err := o.queries.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("failed to get flow: %w", err)
	}

	base.ResetBrowserAutomation()

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
	loopTriggered := false
	var resetMu sync.Mutex
	seenPivotNotes := make(map[string]struct{})
	promotedFindingKeys := make(map[string]struct{})
	var promotedFindingMu sync.Mutex
	seenLeadNotes := make(map[string]struct{})
	seenExclusionNotes := make(map[string]struct{})
	dispatchedSpecs := make(map[string]struct{})
	var dedupeMu sync.Mutex
	browserUnavailableNotified := false
	if restoredBrain, ok := o.restoreBrainSnapshot(flowID); ok {
		brain = restoredBrain
	}
	persistBrainState := func(stage string) {
		brainMu.Lock()
		snapshot := cloneBrain(&brain)
		brainMu.Unlock()
		if snapshot == nil {
			return
		}
		o.persistBrainSnapshot(flowID, &task.ID, stage, snapshot)
	}
	persistBrainState("flow_start")

	// Initialize scope guardrails for this flow
	o.scope = NewScopeEngine(flow.Target)

	// ── Mythos: Scope + private-IP validation ─────────────────────────────
	if err := validateScanTarget(flow.Target); err != nil {
		return fmt.Errorf("scope validation: %w", err)
	}

	// ── Mythos: Register this host in the cross-session knowledge graph ───
	techStr := ""
	if _, err := knowledge.RecordHost(o.knowledgeGraph, flow.Target, techStr, flowID.String()); err != nil {
		log.Printf("[kg] RecordHost failed: %v", err)
	}

	// ── Mythos: WAF fingerprint at scan start (shared across all agents) ──
	{
		wafCtx, cancelWAF := context.WithTimeout(ctx, 10*time.Second)
		wafRes := FingerprintWAF(wafCtx, flow.Target)
		cancelWAF()
		o.wafResultMu.Lock()
		o.wafResult = wafRes
		o.wafResultMu.Unlock()
		if wafRes.Vendor != WAFNone && wafRes.Vendor != WAFUnknown {
			log.Printf("[waf] Detected WAF: %s (confidence=%.2f)", wafRes.Vendor, wafRes.Confidence)
		}
	}

	// Fetch historical insights from cross-flow memory
	historicalCtx := o.memory.FormatInsightsForPrompt(flow.Target)
	if historicalCtx == "" {
		// Fallback to basic historical context if no memory found
		globalPast, _ := o.queries.GetHistoricalContext(flow.Target)
		if globalPast != "" {
			historicalCtx = "[HISTORY] PAST FINDINGS ON THIS TARGET:\n" + globalPast
		}
	}

	// ==========================================
	// EVENT SUBSCRIPTIONS (Flow-Scoped)
	// ==========================================

	// Subscribe to pivot discoveries that warrant a pipeline restart
	o.bus.Subscribe(EventPivotDiscovered, func(data interface{}) {
		note := data.(string)
		note = strings.TrimSpace(note)
		if note == "" {
			return
		}

		resetMu.Lock()
		if _, exists := seenPivotNotes[note]; exists {
			resetMu.Unlock()
			return
		}
		seenPivotNotes[note] = struct{}{}
		loopTriggered = true
		resetMu.Unlock()

		brainMu.Lock()
		brain.PivotContext += "\n- " + note
		brainMu.Unlock()
		persistBrainState("pivot_context")

		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[PIVOT] New attack surface unlocked: %s. Initiating Iterative Feedback Loop...", note[:min(80, len(note))]),
		})
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
			var f Finding
			if err := json.Unmarshal([]byte(note), &f); err == nil {
				if ok, reason := shouldPromoteFinding(&f); ok {
					o.bus.Emit(EventFindingDiscovered, &f)
				} else {
					o.emit(flowID.String(), Event{
						Type:    EventMessage,
						FlowID:  flowID.String(),
						TaskID:  task.ID.String(),
						Content: fmt.Sprintf("[WARN] Finding held for more proof: %s", reason),
					})
					o.bus.Emit(EventLeadDiscovered, fmt.Sprintf("Needs validation: %s at %s", f.Type, f.URL))
				}
			} else {
				o.emit(flowID.String(), Event{
					Type:    EventMessage,
					FlowID:  flowID.String(),
					TaskID:  task.ID.String(),
					Content: "[WARN] Ignoring unstructured finding promotion; retaining it as a lead until concrete proof exists.",
				})
				o.bus.Emit(EventLeadDiscovered, note)
			}
		case "exclusion":
			o.bus.Emit(EventExclusionDiscovered, note)
		case "credentials":
			brainMu.Lock()
			auth := ensureAuthState(&brain.Auth)
			mergeAuthContextFromNote(auth, note)
			updateAuthAttackGraph(&brain, flow.Target, brain.Auth)
			brainMu.Unlock()
			persistBrainState("auth_context")
			o.bus.Emit(EventPivotDiscovered, note)
		case "pivot":
			o.bus.Emit(EventPivotDiscovered, note)
		case "tech":
			brainMu.Lock()
			if brain.Tech == nil {
				brain.Tech = DefaultTechStack()
			}
			o.updateTechStackFromNote(brain.Tech, note)
			brainMu.Unlock()
			persistBrainState("tech_profile")
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("[TECHSTACK] Technology Stack Identified: %s", note),
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
		normalized := normalizeBrainNote(note)
		if normalized == "" {
			return
		}
		dedupeMu.Lock()
		if _, exists := seenLeadNotes[normalized]; exists {
			dedupeMu.Unlock()
			return
		}
		seenLeadNotes[normalized] = struct{}{}
		dedupeMu.Unlock()
		brainMu.Lock()
		brain.Leads = append(brain.Leads, normalized)
		updateLeadAttackGraph(&brain, flow.Target, normalized)
		brainMu.Unlock()
		persistBrainState("lead")
		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[BRAIN] Synapse [lead]: %s", normalized),
		})
	})

	o.bus.Subscribe(EventFindingDiscovered, func(data interface{}) {
		var finding *Finding
		switch v := data.(type) {
		case *Finding:
			finding = cloneFinding(v)
		case Finding:
			finding = cloneFinding(&v)
		case string:
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("Finding kept as lead until structured evidence exists: %s", v),
			})
			o.bus.Emit(EventLeadDiscovered, v)
			return
		default:
			return
		}

		if ok, reason := shouldPromoteFinding(finding); !ok {
			o.recordEvidencePack(flowID, &task.ID, subtaskIDFromFinding(finding), finding, models.EvidenceStatusNeedsProof, reason)
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("Finding not promoted: %s", reason),
			})
			o.bus.Emit(EventLeadDiscovered, fmt.Sprintf("Needs stronger validation: %s at %s", finding.Type, finding.URL))
			return
		}

		o.recordEvidencePack(flowID, &task.ID, subtaskIDFromFinding(finding), finding, models.EvidenceStatusConfirmed, "validated and promoted into the brain")

		key := findingFingerprint(finding)
		promotedFindingMu.Lock()
		if _, exists := promotedFindingKeys[key]; exists {
			promotedFindingMu.Unlock()
			return
		}
		promotedFindingKeys[key] = struct{}{}
		promotedFindingMu.Unlock()

		brainMu.Lock()
		// ── Mythos: Auto-compute CVSS score on promotion ──────────────────
		cvss := ScoreFinding(finding)
		if finding.Evidence == nil {
			finding.Evidence = make(map[string]interface{})
		}
		finding.Evidence["cvss_score"] = cvss.Score
		finding.Evidence["cvss_vector"] = cvss.Vector
		finding.Evidence["cvss_severity"] = cvss.Severity
		finding.Evidence["cvss_exploitable"] = cvss.Exploitable
		// Auto-upgrade severity to match CVSS if CVSS is higher
		if cvss.Severity == "Critical" && strings.ToLower(finding.Severity) != "critical" {
			finding.Severity = "critical"
		}
		rem := RemediationFor(finding.Type)
		finding.Evidence["remediation_summary"] = rem.Summary
		finding.Evidence["remediation_priority"] = rem.Priority
		brain.Findings = append(brain.Findings, finding)
		updateFindingAttackGraph(&brain, flow.Target, finding)
		brainMu.Unlock()
		persistBrainState("finding")
		note := fmt.Sprintf("%s %s", finding.Type, finding.URL)
		o.emit(flowID.String(), Event{
			Type:    EventToolResult,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: formatFindingReport(finding),
			Metadata: map[string]interface{}{
				"tool": "report_findings",
			},
		})

		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[BRAIN] Synapse [finding]: %s", note),
		})
	})

	o.bus.Subscribe(EventExclusionDiscovered, func(data interface{}) {
		note := data.(string)
		normalized := normalizeBrainNote(note)
		if normalized == "" {
			return
		}
		dedupeMu.Lock()
		if _, exists := seenExclusionNotes[normalized]; exists {
			dedupeMu.Unlock()
			return
		}
		seenExclusionNotes[normalized] = struct{}{}
		dedupeMu.Unlock()
		brainMu.Lock()
		brain.Exclusions = append(brain.Exclusions, normalized)
		brainMu.Unlock()
		persistBrainState("exclusion")
		o.emit(flowID.String(), Event{
			Type:    EventMessage,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[BRAIN] Synapse [exclusion]: %s", normalized),
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
		persistBrainState("causal_node")
		o.emit(flowID.String(), Event{
			Type:    EventCausalNodeAddedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[GRAPH] Causal Graph: Added node [%s] %s", node.NodeType, node.ID),
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
		persistBrainState("causal_node")
		o.emit(flowID.String(), Event{
			Type:    EventCausalNodeUpdatedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[GRAPH] Causal Graph: Updated node %s (Status: %s, Confidence: %.2f)", id, status, confidence),
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
		persistBrainState("causal_edge")
		o.emit(flowID.String(), Event{
			Type:    EventCausalEdgeAddedWS,
			FlowID:  flowID.String(),
			TaskID:  task.ID.String(),
			Content: fmt.Sprintf("[GRAPH] Causal Graph: Added relationship %s --[%s]--> %s", edge.SourceID, edge.Label, edge.TargetID),
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

	for _, w := range o.workers {
		go w.Start(ctx)
	}
	defer func() {
		for _, w := range o.workers {
			w.Stop()
		}
	}()

	// ── Mythos: Adaptive convergence tracking ──────────────────────────────
	prevFindingCount := 0
	stableLoops := 0
	const maxStableLoops = 2 // Stop after 2 loops with no new high-confidence findings

	for loopCount := 1; loopCount <= maxLoops; loopCount++ {
		// Reset trigger for each loop iteration until it's set again
		resetMu.Lock()
		loopTriggered = false
		resetMu.Unlock()

		// ==========================================
		// PIPELINE: Start/Reset -> RECONNAISSANCE
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

		reconSubtask, err := o.createLedgerSubTask(
			task.ID,
			nil,
			"Phase 1: Reconnaissance",
			"Map attack surface",
			models.AgentTypeOrchestrator,
			models.SubTaskKindPhase,
			"recon",
			flow.Target,
			"high",
			fmt.Sprintf("phase:%d:recon", loopCount),
			"Broad reconnaissance and target mapping",
			map[string]any{"phase": "recon", "loop": loopCount},
		)
		if err != nil {
			return err
		}

		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[PHASE-1] Initiating Phase 1: Reconnaissance"})

		reconPrompt := o.prompts.BuildPhasePrompt("RECONNAISSANCE", o.prompts.Phases.Recon, flow.Target, userPrompt, historicalCtx)

		// ── Mythos: Per-phase timeout — Recon capped at 25 minutes ──────────
		reconCtx, cancelRecon := context.WithTimeout(ctx, 25*time.Minute)
		defer cancelRecon()
		if o.conductor != nil {
			o.conductor.RegisterAgent(reconSubtask.ID, "Reconnaissance", flow.Target, cancelRecon)
			defer o.conductor.DeregisterAgent(reconSubtask.ID, StatusComplete)
		}

		reconResult := o.runAgentLoop(reconCtx, flowID, task.ID, reconSubtask.ID, reconPrompt, "Start Recon.", &brain, &brainMu)

		// ==========================================
		// PHASE 1.5: SPA DEEP CRAWL (Headless Discovery)
		// ==========================================
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[CRAWL] Phase 1.5: SPA Deep Crawl (Headless Browser Discovery)"})

		crawlCtx, cancelCrawl := context.WithTimeout(ctx, 30*time.Second)
		crawlResults, crawlErr := base.RunCrawl(crawlCtx, flow.Target, base.DefaultBrowserOptions())
		cancelCrawl()

		var spaSummary string
		if crawlErr != nil {
			spaSummary = fmt.Sprintf("SPA crawl skipped: %v", crawlErr)
			if base.IsBrowserUnavailableError(crawlErr) {
				if !browserUnavailableNotified {
					o.emit(flowID.String(), Event{
						Type:    EventMessage,
						FlowID:  flowID.String(),
						TaskID:  task.ID.String(),
						Content: "[WARN] Browser automation disabled for this run. SPA crawl and visual validation will be skipped.",
					})
					browserUnavailableNotified = true
				}
			} else {
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[WARN] SPA crawl failed (target may not support headless browsing). Continuing..."})
			}
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
			persistBrainState("browser_recon")

			spaSummary = fmt.Sprintf("SPA crawl discovered %d dynamic links and %d interactive inputs.", len(crawlResults.Links), len(crawlResults.Inputs))
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("[CRAWL] %s", spaSummary),
			})
		}

		reconResult += "\n\nSPA DEEP CRAWL RESULTS:\n" + spaSummary

		// ==========================================
		// PIPELINE: RECON -> DISCOVERY (Strategy/Planner)
		// ==========================================
		if err := o.pipeline.Advance("Recon complete", map[string]interface{}{
			"leads_found": len(brain.Leads),
		}); err != nil {
			log.Printf("[pipeline] Advance to DISCOVERY failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		// ==========================================
		// PIPELINE: DISCOVERY -> STRATEGY (Planner)
		// ==========================================
		if err := o.pipeline.Advance("Discovery phase (combined with Strategy)", nil); err != nil {
			log.Printf("[pipeline] Advance to STRATEGY failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		plannerSubtask, err := o.createLedgerSubTask(
			task.ID,
			nil,
			"Phase 2: Intelligent Planner",
			"Analyze and dispatch",
			models.AgentTypeOrchestrator,
			models.SubTaskKindPhase,
			"planner",
			flow.Target,
			"high",
			fmt.Sprintf("phase:%d:planner", loopCount),
			"Consolidate recon state into bounded specialist tasks",
			map[string]any{"phase": "planner", "loop": loopCount},
		)
		if err != nil {
			return err
		}
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[PHASE-2] Initiating Phase 2: Planner (Dynamic Swarm Construction)"})

		brainMu.Lock()
		plannerInput := "RECON SUMMARY:\n" + reconResult + "\n\n[BRAIN] LEADS (LEADS TO CONSOLIDATE):\n"
		bJSON, _ := json.MarshalIndent(brain, "", "  ")
		plannerInput += string(bJSON)
		brainMu.Unlock()

		plannerPrompt := o.prompts.BuildPhasePrompt("THINKING & CONSOLIDATION", o.prompts.Phases.Planner, flow.Target, userPrompt, "")

		// ── Mythos: Per-phase timeout — Planner capped at 10 minutes ─────────
		plannerCtx, cancelPlanner := context.WithTimeout(ctx, 10*time.Minute)
		defer cancelPlanner()
		if o.conductor != nil {
			o.conductor.RegisterAgent(plannerSubtask.ID, "Thinking & Consolidation", flow.Target, cancelPlanner)
			defer o.conductor.DeregisterAgent(plannerSubtask.ID, StatusComplete)
		}

		// ── Mythos: Generate pre-dispatch attack hypotheses ────────────────
		brainMu.Lock()
		hyps, hypErr := o.hypothesisEngine.Generate(plannerCtx, flow.Target, brain.Leads, brain.Tech, brain.Findings)
		brainMu.Unlock()
		// Track hypotheses for this loop iteration so they can be refined post-exploitation
		currentHypotheses := hyps
		if hypErr == nil && len(hyps) > 0 {
			hypJSON, _ := json.Marshal(hyps)
			o.emit(flowID.String(), Event{
				Type:     EventMessage,
				FlowID:   flowID.String(),
				TaskID:   task.ID.String(),
				Content:  fmt.Sprintf("[HYPOTHESIS] Generated %d attack hypotheses (top priority: %s → %s)", len(hyps), hyps[0].VulnClass, hyps[0].Title),
				Metadata: map[string]interface{}{"hypotheses": json.RawMessage(hypJSON)},
			})
			plannerInput += "\n\n[HYPOTHESIS ENGINE] PRIORITIZED ATTACK HYPOTHESES:\n" + string(hypJSON)
		}
		// ────────────────────────────────────────────────────────────────────

		// ── Mythos: Zero-day pattern enrichment ─────────────────────────────
		brainMu.Lock()
		zdPatterns := MatchPatterns(brain.Leads, brain.Tech)
		brainMu.Unlock()
		if len(zdPatterns) > 0 {
			type zdProbeEntry struct {
				Pattern   string   `json:"pattern"`
				Category  string   `json:"category"`
				CWE       string   `json:"cwe"`
				Impact    string   `json:"impact"`
				ProbeURLs []string `json:"probe_urls"`
			}
			zdEntries := make([]zdProbeEntry, 0, len(zdPatterns))
			zdNames := make([]string, 0, len(zdPatterns))
			for _, p := range zdPatterns {
				zdNames = append(zdNames, p.Name)
				probeURLs := BuildZeroDayProbeURLs(p, flow.Target)
				zdEntries = append(zdEntries, zdProbeEntry{
					Pattern:   p.Name,
					Category:  p.Category,
					CWE:       p.CWE,
					Impact:    p.Impact,
					ProbeURLs: probeURLs,
				})
			}
			zdJSON, _ := json.Marshal(zdEntries)
			o.emit(flowID.String(), Event{
				Type:     EventMessage,
				FlowID:   flowID.String(),
				TaskID:   task.ID.String(),
				Content:  fmt.Sprintf("[0-DAY] Matched %d zero-day patterns: %v", len(zdPatterns), zdNames),
				Metadata: map[string]interface{}{"zero_day_probes": json.RawMessage(zdJSON)},
			})
			plannerInput += "\n\n[ZERO-DAY PATTERNS WITH PROBE URLs]: " + string(zdJSON)
		}
		// ────────────────────────────────────────────────────────────────────

		plannerResult := o.runAgentLoop(plannerCtx, flowID, task.ID, plannerSubtask.ID, plannerPrompt, "Consolidate these leads and dispatch specialists:\n"+plannerInput, &brain, &brainMu)

		// Schema Validation: Parse planner output with structured validation
		var agentSpecs []SwarmAgentSpec
		plannerOutput, parseErr := o.parsePlannerOutputWithRetry(plannerCtx, plannerPrompt, plannerResult)
		if parseErr != nil {
			// Schema validation failed -- log the error and fall back to defaults
			log.Printf("[schema] Planner output validation failed: %v", parseErr)
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("[WARN] Planner output failed schema validation: %v. Using default specialist dispatch.", parseErr),
			})
			brainMu.Lock()
			agentSpecs = buildFallbackAgentSpecs(flow.Target, &brain)
			brainMu.Unlock()
		} else {
			// Convert schema specs to orchestrator specs
			for _, spec := range plannerOutput.Specs {
				agentSpecs = append(agentSpecs, SwarmAgentSpec{
					Type:         spec.Type,
					Target:       spec.Target,
					Context:      spec.Context,
					Hypothesis:   spec.Hypothesis,
					Proof:        spec.Proof,
					RequiresAuth: spec.RequiresAuth,
					AuthContext:  spec.AuthContext,
					Priority:     spec.Priority,
				})
			}
		}

		agentSpecs = filterDispatchSpecs(agentSpecs, dispatchedSpecs, flow.Target, base.BrowserAvailable())

		o.emit(flowID.String(), Event{
			Type:     EventMessage,
			FlowID:   flowID.String(),
			TaskID:   task.ID.String(),
			Content:  fmt.Sprintf("[PLAN] Planner dispatching %d specialized agents", len(agentSpecs)),
			Metadata: map[string]interface{}{"agents": agentSpecs},
		})

		// ==========================================
		// PIPELINE: STRATEGY -> EXPLOITATION (Swarm)
		// ==========================================
		if err := o.pipeline.Advance("Strategy complete, dispatching specialists", map[string]interface{}{
			"specialists_dispatched": len(agentSpecs),
		}); err != nil {
			log.Printf("[pipeline] Advance to EXPLOITATION failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

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
					Content: fmt.Sprintf("[RAG] Enhancing %s agent with payloads from RAG Knowledge Base.", spec.Type),
				})
			}

			// ── Mythos: KG effective-payload injection ──────────────────────────
			// Build a concrete []string of proven payloads that agents can use directly.
			brainMu.Lock()
			techStackStr := ""
			if brain.Tech != nil {
				techStackStr = brain.Tech.Lang
			}
			brainMu.Unlock()
			var suggestedPayloads []string
			if kgPayloads, kgErr := o.knowledgeGraph.GetEffectivePayloads(techStackStr, spec.Type); kgErr == nil && len(kgPayloads) > 0 {
				kgContext := "\n\n[KNOWLEDGE GRAPH] PROVEN PAYLOADS FROM PREVIOUS SCANS (high success rate):\n"
				for i, p := range kgPayloads {
					if i >= 5 {
						break
					}
					if pl, ok := p.Properties["payload"].(string); ok && pl != "" {
						kgContext += "- " + pl + "\n"
						suggestedPayloads = append(suggestedPayloads, pl)
					}
				}
				enhancedContext += kgContext
			}

			// ── Mythos: PayloadEngine adaptive generation for high-priority specs ─
			if spec.Priority == "critical" || spec.Priority == "high" {
				if o.payloadEngine != nil && o.llmProvider != nil {
					brainMu.Lock()
					ts := brain.Tech
					brainMu.Unlock()
					peCtx, cancelPE := context.WithTimeout(ctx, 8*time.Second)
					if adaptivePayloads, peErr := o.payloadEngine.GenerateNextPayloads(peCtx, resolveDispatchTarget(flow.Target, spec.Target), "", spec.Type, ts); peErr == nil && len(adaptivePayloads) > 0 {
						suggestedPayloads = append(adaptivePayloads, suggestedPayloads...)
						enhancedContext += "\n\n[ADAPTIVE PAYLOADS] LLM-generated bypass variants:\n"
						for _, ap := range adaptivePayloads {
							enhancedContext += "- " + ap + "\n"
						}
					}
					cancelPE()
				}
			}

			// ── Mythos: WAF fingerprint injection ──────────────────────────────
			o.wafResultMu.RLock()
			wafSnap := o.wafResult
			o.wafResultMu.RUnlock()
			if wafSnap.Vendor != WAFNone && wafSnap.Vendor != WAFUnknown && wafSnap.Vendor != "" {
				// Use first suggested payload (or generic) as base for WAF-specific bypass mutation
				basePayloadForWAF := ""
				if len(suggestedPayloads) > 0 {
					basePayloadForWAF = suggestedPayloads[0]
				}
				bypassPayloads := WAFBypassPayloads(wafSnap.Vendor, basePayloadForWAF)
				if len(bypassPayloads) > 0 {
					suggestedPayloads = append(bypassPayloads[:min(5, len(bypassPayloads))], suggestedPayloads...)
				}
				wafCtx := fmt.Sprintf("\n\n[WAF DETECTED: %s (confidence=%.0f%%)] Vendor-specific bypass payloads prepended to suggested_payloads.",
					wafSnap.Vendor, wafSnap.Confidence*100)
				enhancedContext += wafCtx
			}

			var authSnapshot *AuthState
			brainMu.Lock()
			spec.Context = enhancedContext
			spec = enrichSwarmAgentSpec(flow.Target, spec, brain.Auth)
			updateHypothesisAttackGraph(&brain, flow.Target, spec)
			authSnapshot = brain.Auth
			brainMu.Unlock()
			persistBrainState("hypothesis_dispatch")

			queueName := normalizeSpecialistName(spec.Type)
			dispatchKey := dispatchFingerprint(spec, flow.Target)
			resolvedTarget := resolveDispatchTarget(flow.Target, spec.Target)
			graphNodeID := attackGraphNodeID("hypothesis", dispatchKey)
			specialistMetadata := map[string]any{
				"spec_type":         spec.Type,
				"queue_name":        queueName,
				"priority":          normalizePriority(spec.Priority),
				"dispatch_to":       resolvedTarget,
				"hypothesis":        spec.Hypothesis,
				"proof_requirement": spec.Proof,
				"requires_auth":     spec.RequiresAuth,
				"auth_context":      spec.AuthContext,
				"attack_graph_node": graphNodeID,
			}
			specialistSubTask, err := o.createLedgerSubTask(
				task.ID,
				&plannerSubtask.ID,
				fmt.Sprintf("%s Specialist", spec.Type),
				strings.TrimSpace(spec.Context),
				models.AgentTypeExecutor,
				models.SubTaskKindSpecialist,
				queueName,
				resolveDispatchTarget(flow.Target, spec.Target),
				normalizePriority(spec.Priority),
				dispatchKey,
				enhancedContext,
				specialistMetadata,
			)
			if err != nil {
				log.Printf("[ledger] failed to create specialist subtask for %s: %v", spec.Type, err)
				continue
			}
			o.recordHypothesisPack(flowID, task.ID, &specialistSubTask.ID, spec, flow.Target)
			payload := buildWorkerPayload(flow.Target, spec, enhancedContext, authSnapshot)
			payload["_flow_id"] = flowID.String()
			payload["_task_id"] = task.ID.String()
			payload["_subtask_id"] = specialistSubTask.ID.String()
			payload["_dispatch_fingerprint"] = dispatchKey
			// ── Mythos: inject concrete payload slice so agents can use it directly ──
			if len(suggestedPayloads) > 0 {
				payload["suggested_payloads"] = suggestedPayloads
			}
			if err := o.queueMgr.Route(queueName, payload, flowID.String()); err != nil {
				log.Printf("[queue] Route to %s failed: %v", queueName, err)
				o.updateLedgerSubTask(
					specialistSubTask.ID,
					models.SubTaskStatusFailed,
					err.Error(),
					models.SubTaskOutcomeBlockedByRuntime,
					map[string]any{"queue_name": queueName, "route_error": err.Error()},
				)
				continue
			}
			dedupeMu.Lock()
			dispatchedSpecs[dispatchKey] = struct{}{}
			dedupeMu.Unlock()
		}

		// Emit queue metrics to frontend after dispatch
		o.emitQueueStats(flowID.String(), task.ID.String())

		// Wait for queues to drain or flow timeout
		o.queueMgr.DrainAll(30 * time.Minute)

		resetMu.Lock()
		shouldLoop := loopTriggered && len(brain.Findings) == 0
		resetMu.Unlock()

		// If a specialist found a credential, break immediate phase and restart loop
		if shouldLoop {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[WARN] Interrupting current validation phase to start new Iterative Recon loop."})
			continue
		}

		// ── Mythos: Convergence detection — stop early if no new findings ───
		brainMu.Lock()
		currentFindingCount := len(brain.Findings)
		brainMu.Unlock()
		if currentFindingCount <= prevFindingCount {
			stableLoops++
			if stableLoops >= maxStableLoops && loopCount > 1 {
				o.emit(flowID.String(), Event{
					Type:    EventMessage,
					FlowID:  flowID.String(),
					TaskID:  task.ID.String(),
					Content: fmt.Sprintf("[CONVERGENCE] No new findings in %d consecutive loops. Attack surface exhausted — advancing to reporting.", stableLoops),
				})
				// Skip to reporting by not continuing the loop
			}
		} else {
			stableLoops = 0
		}
		prevFindingCount = currentFindingCount
		// ─────────────────────────────────────────────────────────────────────

		var swarmResults string = "Asynchronous swarm analysis completed."

		// ── Mythos: Hypothesis Refinement ──────────────────────────────────────
		// After each exploitation round, refine hypothesis confidence based on
		// whether the corresponding vuln class was actually confirmed in findings.
		brainMu.Lock()
		confirmedTypes := make(map[string]bool)
		for _, f := range brain.Findings {
			confirmedTypes[strings.ToLower(f.Type)] = true
		}
		for i, hyp := range currentHypotheses {
			vulnLower := strings.ToLower(hyp.VulnClass)
			if confirmedTypes[vulnLower] {
				currentHypotheses[i] = o.hypothesisEngine.RefineSingle(ctx, hyp, "specialist confirmed "+hyp.VulnClass, true)
			} else {
				currentHypotheses[i] = o.hypothesisEngine.RefineSingle(ctx, hyp, "specialist found no "+hyp.VulnClass, false)
			}
		}
		// Record confirmed findings into the knowledge graph for cross-session learning
		for _, f := range brain.Findings {
			ts := ""
			if brain.Tech != nil {
				ts = brain.Tech.Lang
			}
			hostID := "host:" + strings.ReplaceAll(strings.ReplaceAll(flow.Target, "://", "-"), "/", "-")
			if kgErr := knowledge.RecordFinding(o.knowledgeGraph, hostID, flowID.String(), f.Type, f.URL, f.Payload, ts, f.Confidence); kgErr != nil {
				log.Printf("[kg] RecordFinding error: %v", kgErr)
			}
		}
		// ── Feed refined hypotheses back into Brain so next planner sees them ──
		// Keep only hypotheses with confidence > 0.2 (prune exhausted ones)
		var activeHyps []AttackHypothesis
		for _, h := range currentHypotheses {
			if h.Confidence > 0.2 {
				activeHyps = append(activeHyps, h)
			}
		}
		brain.Hypotheses = activeHyps
		brainMu.Unlock()

		if len(currentHypotheses) > 0 {
			refinedJSON, _ := json.Marshal(currentHypotheses)
			o.emit(flowID.String(), Event{
				Type:     EventMessage,
				FlowID:   flowID.String(),
				TaskID:   task.ID.String(),
				Content:  fmt.Sprintf("[HYPOTHESIS] Refined %d hypotheses post-exploitation (%d still active)", len(currentHypotheses), len(activeHyps)),
				Metadata: map[string]interface{}{"hypotheses": json.RawMessage(refinedJSON)},
			})
		}
		// ────────────────────────────────────────────────────────────────────────

		// ==========================================
		// PIPELINE: EXPLOITATION -> VALIDATION (PoC Generator)
		// ==========================================
		if err := o.pipeline.Advance("Exploitation complete", map[string]interface{}{
			"swarm_agents": len(agentSpecs),
			"findings":     len(brain.Findings),
		}); err != nil {
			log.Printf("[pipeline] Advance to VALIDATION failed: %v", err)
		}
		o.emitPipelineEvent(flowID.String(), task.ID.String())

		pocSubtask, _ := o.createLedgerSubTask(
			task.ID,
			nil,
			"Phase 4: PoC Generator",
			"Create reproducible evidence",
			models.AgentTypeReporter,
			models.SubTaskKindValidation,
			"poc",
			flow.Target,
			"high",
			fmt.Sprintf("phase:%d:poc", loopCount),
			"Turn validated findings into reproducible proofs",
			map[string]any{"phase": "poc", "loop": loopCount},
		)
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
				Content: fmt.Sprintf("[POST-EXPLOIT] High-impact vulnerability confirmed (%s). Escalating...", criticalFinding.Type),
			})

			peSubtask, _ := o.createLedgerSubTask(
				task.ID,
				nil,
				"Phase 4: Post-Exploitation",
				"Escalate confirmed vulnerability",
				models.AgentTypeExecutor,
				models.SubTaskKindPostExploit,
				"post_exploit",
				criticalFinding.URL,
				strings.ToLower(criticalFinding.Severity),
				fmt.Sprintf("phase:%d:post-exploit:%s", loopCount, findingFingerprint(criticalFinding)),
				"Escalate a high-impact validated finding",
				map[string]any{"finding_type": criticalFinding.Type, "finding_url": criticalFinding.URL},
			)
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

		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[PHASE-5] Initiating Phase 5: PoC Generator (Validating Findings)"})

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
		o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(), Content: "[VISUAL] Phase 5.5: Visual Validation & OOB Callback Check"})

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
		if len(xssFindings) > 0 && !base.BrowserAvailable() {
			if !browserUnavailableNotified {
				o.emit(flowID.String(), Event{
					Type:    EventMessage,
					FlowID:  flowID.String(),
					TaskID:  task.ID.String(),
					Content: "[WARN] Skipping visual validation because browser automation is disabled for this run.",
				})
				browserUnavailableNotified = true
			}
		}
		for _, f := range xssFindings {
			if !base.BrowserAvailable() {
				break
			}
			validCtx, cancelValid := context.WithTimeout(ctx, 15*time.Second)
			confirmed, reason, screenshot, err := o.validator.ValidateXSS(validCtx, f.URL, f.Parameter, f.Payload, strings.ToUpper(f.Method) == "POST")
			cancelValid()

			if err != nil {
				if base.IsBrowserUnavailableError(err) {
					if !browserUnavailableNotified {
						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  task.ID.String(),
							Content: "[WARN] Browser automation became unavailable during visual validation. Remaining browser-driven checks will be skipped.",
						})
						browserUnavailableNotified = true
					}
					break
				}
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
					Content: fmt.Sprintf("[WARN] Visual validation failed for %s at %s: %v", f.Type, f.URL, err)})
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
					Content: fmt.Sprintf("[OK] VISUALLY CONFIRMED: %s at %s -- %s", f.Type, f.URL, reason)})
			} else {
				o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
					Content: fmt.Sprintf("[FAIL] Not visually confirmed: %s at %s -- %s", f.Type, f.URL, reason)})
			}
		}

		// OOB Polling: Check for blind vulnerability callbacks
		oobInteractions := o.oobManager.GetInteractions(flowID.String())
		if len(oobInteractions) > 0 {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
				Content: fmt.Sprintf("[OOB] CONFIRMED: %d blind vulnerabilities received callbacks!", len(oobInteractions))})

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
			persistBrainState("oob_finding")

			pocResult += fmt.Sprintf("\n\n## OOB Confirmed Findings\n%d blind vulnerabilities confirmed via out-of-band callbacks.\n", len(oobInteractions))
		} else if o.oobManager.PendingCount() > 0 {
			o.emit(flowID.String(), Event{Type: EventMessage, FlowID: flowID.String(), TaskID: task.ID.String(),
				Content: fmt.Sprintf("⏳ %d OOB tokens still pending (callbacks may arrive later).", o.oobManager.PendingCount())})
		}

		// ==========================================
		// PIPELINE: VALIDATION -> REPORTING -> COMPLETE
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
		persistBrainState("dedupe")

		if dedupedCount < originalCount {
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  task.ID.String(),
				Content: fmt.Sprintf("[DEDUP] Advanced Deduplication: Compressed %d findings into %d unique root causes.", originalCount, dedupedCount),
			})
		}

		// Save this flow's findings to cross-flow memory for future scans
		o.memory.SaveBrainFindings(flow.Target, flowID, brain.Leads, brain.Findings, brain.Exclusions)
		persistBrainState("flow_complete")

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

		// Final transition: REPORTING -> COMPLETE
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
	o.updateLedgerSubTask(subtaskID, models.SubTaskStatusRunning, "", models.SubTaskOutcomeRunning, map[string]any{
		"mode": "llm_loop",
	})

	successCount := 0
	var chatMsgs []models.ChatMessage
	chatMsgs = append(chatMsgs, models.ChatMessage{Role: "user", Content: userPrompt})

	// Feature: Redirect Tracking (302 Intelligence)
	redirectTracker := NewRedirectTracker()

	// Feature: Forced Reflection on Repeated Failure
	consecutiveFailures := 0
	const failureReflectionThreshold = 3
	const failureTerminateThreshold = 5
	persistLoopBrainState := func(stage string) {
		brainMu.Lock()
		snapshot := cloneBrain(brain)
		brainMu.Unlock()
		if snapshot == nil {
			return
		}
		o.persistBrainSnapshot(flowID, &taskID, stage, snapshot)
	}

	var lastResult string
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			o.updateLedgerSubTask(subtaskID, models.SubTaskStatusFailed, "Cancelled", models.SubTaskOutcomeBlockedByRuntime, map[string]any{
				"reason": "context cancelled",
			})
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
		if authSummary := buildAuthContextSummary(brain.Auth); authSummary != "" {
			effectiveSystemPrompt += "\n\nAUTHENTICATION CONTEXT (preserve this across specialists):\n" + authSummary + "\nReuse this state for authenticated exploration and keep cookies, headers, and tokens intact."
		}
		brainMu.Unlock()

		// Feature: Context Compression -- summarize old messages to prevent token overflow
		if shouldCompress(chatMsgs) {
			log.Printf("[compress] Triggering conversation compression (%d messages, ~%d tokens)", len(chatMsgs), estimateTokens(chatMsgs))
			o.emit(flowID.String(), Event{
				Type:    EventMessage,
				FlowID:  flowID.String(),
				TaskID:  taskID.String(),
				Content: fmt.Sprintf("[COMPRESS] Compressing conversation history (%d messages -> summary + %d recent)", len(chatMsgs), CompressKeepRecent),
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
			o.updateLedgerSubTask(subtaskID, models.SubTaskStatusFailed, err.Error(), models.SubTaskOutcomeBlockedByRuntime, map[string]any{
				"reason": "llm completion failed",
			})
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
						inScope, reason = o.scope.ValidateToolArgs(tc.Name, json.RawMessage(tc.Arguments))
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
									Content: "[ALERT] [WAF BLOCK] Evasion strategy triggered.",
								})
								strategy := o.strategist.SuggestedEncoding(tc.Name, output)
								o.emit(flowID.String(), Event{
									Type:    EventMessage,
									FlowID:  flowID.String(),
									TaskID:  taskID.String(),
									Content: fmt.Sprintf("[STRATEGY] Strategist suggesting shift to: %s", strategy),
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
							Content: fmt.Sprintf("[AUTH] [AUTH WALL] %d redirects to %s detected. Pivoting strategy.", insight.RedirectCount, insight.LoginURL),
						})

						// Map login page as high-priority target in Brain
						brainMu.Lock()
						brain.Leads = append(brain.Leads, fmt.Sprintf("[AUTH-TARGET] Login page at %s - try auth bypass, default credentials, or credential stuffing", insight.LoginURL))
						auth := ensureAuthState(&brain.Auth)
						if auth.LoginURL == "" {
							auth.LoginURL = insight.LoginURL
						}
						appendAuthNote(auth, insight.Message)
						updateAuthAttackGraph(brain, o.scope.RawTarget, brain.Auth)
						brainMu.Unlock()
						persistLoopBrainState("auth_target")
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
						auth := ensureAuthState(&brain.Auth)
						mergeAuthContextFromNote(auth, res)
						appendAuthNote(auth, fmt.Sprintf("Potential credentials detected in tool output for %s", tc.Name))
						updateAuthAttackGraph(brain, o.scope.RawTarget, brain.Auth)
						brainMu.Unlock()
						persistLoopBrainState("auth_context")
						// Emit credential discovery pivot
						o.bus.Emit(EventPivotDiscovered, fmt.Sprintf("Potential credentials detected in tool output for %s", tc.Name))
					}
				}

				// ============================================
				// Feature: Forced Reflection on Repeated Failure
				// ============================================
				isFailure := isToolOutputFailure(res)
				if isFailure {
					consecutiveFailures++

					if consecutiveFailures >= failureTerminateThreshold {
						// Hard stop -- too many failures, agent is stalled
						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: fmt.Sprintf("[STALLED] %d consecutive failures -- terminating this agent to save resources.", consecutiveFailures),
						})
						lastResult = fmt.Sprintf("Terminated: %d consecutive failures detected. Agent is stalled on an unproductive approach.", consecutiveFailures)
						goto done
					}

					if consecutiveFailures >= failureReflectionThreshold {
						reflectionMsg := fmt.Sprintf(
							"[WARN] FORCED REFLECTION: You've had %d consecutive failures. "+
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
							Content: fmt.Sprintf("[REFLECT] [FORCED REFLECTION] %d consecutive failures -- injecting strategy pivot.", consecutiveFailures),
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
						vetoMsg := fmt.Sprintf("[VETO] REFLECTOR VETO: Your reported finding was REJECTED by the auditor.\nREASON: %s\n\nYou MUST continue working to find actual proof, or try a different approach. Do not call complete_task until you have concrete proof in the logs.", vetoReason)

						chatMsgs = append(chatMsgs, models.ChatMessage{
							Role:    "user",
							Content: vetoMsg,
						})

						o.emit(flowID.String(), Event{
							Type:    EventMessage,
							FlowID:  flowID.String(),
							TaskID:  taskID.String(),
							Content: "[VETO] Finding rejected. " + vetoReason,
						})

						// Continue the loop, forcing the agent to try again
						continue
					}

					// Reflector approved, or it was a valid finding.
					o.emit(flowID.String(), Event{
						Type:    EventMessage,
						FlowID:  flowID.String(),
						TaskID:  taskID.String(),
						Content: "[OK] [REFLECTOR APPROVED] Finding validated against execution logs.",
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
								Content: "[VICTORY] HIERARCHY TRIGGERED: " + reason,
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
	status, outcome := outcomeForLoopResult(lastResult)
	o.updateLedgerSubTask(subtaskID, status, lastResult, outcome, map[string]any{
		"mode":          "llm_loop",
		"success_count": successCount,
	})
	return lastResult
}

func (o *Orchestrator) parsePlannerOutputWithRetry(ctx context.Context, plannerPrompt string, plannerResult string) (schema.PlannerOutput, error) {
	plannerOutput, parseErr := schema.ParsePlannerOutput(plannerResult)
	if parseErr == nil {
		return plannerOutput, nil
	}

	retryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := o.llmProvider.Complete(retryCtx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: plannerPrompt},
			{Role: "user", Content: schema.CorrectionPrompt(parseErr, plannerResult) + "\n\nOriginal response:\n" + plannerResult},
		},
	})
	if err != nil {
		return schema.PlannerOutput{}, parseErr
	}

	return schema.ParsePlannerOutput(resp.Content)
}

func cloneFinding(f *Finding) *Finding {
	if f == nil {
		return nil
	}

	clone := *f
	if f.Evidence != nil {
		clone.Evidence = make(map[string]interface{}, len(f.Evidence))
		for k, v := range f.Evidence {
			clone.Evidence[k] = v
		}
	}
	return &clone
}

func findingFingerprint(f *Finding) string {
	if f == nil {
		return ""
	}
	return strings.ToLower(strings.Join([]string{
		f.Type,
		f.URL,
		f.Parameter,
		f.Payload,
		f.Method,
	}, "|"))
}

func shouldPromoteFinding(f *Finding) (bool, string) {
	if f == nil {
		return false, "finding is nil"
	}
	if err := ValidateFinding(f); err != nil {
		return false, err.Error()
	}
	proof, reason := classifyFindingProof(f)
	if proof == proofClassNone {
		return false, reason
	}
	if f.Evidence == nil {
		f.Evidence = make(map[string]interface{})
	}
	f.Evidence["proof_class"] = string(proof)
	if f.Confidence > 0 && f.Confidence < 0.8 {
		return false, fmt.Sprintf("confidence %.2f below promotion threshold for %s proof", f.Confidence, proof)
	}
	return true, fmt.Sprintf("promoted with %s proof", proof)
}

func findingHasConcreteEvidence(f *Finding) bool {
	proof, _ := classifyFindingProof(f)
	return proof != proofClassNone
}

func formatFindingReport(f *Finding) string {
	if f == nil {
		return "## Discovery\nNo finding details available."
	}

	description := fmt.Sprintf("Confirmed %s on %s", f.Type, f.URL)
	if f.Parameter != "" {
		description += fmt.Sprintf(" via parameter `%s`", f.Parameter)
	}
	if f.Payload != "" {
		description += fmt.Sprintf(" using payload `%s`", f.Payload)
	}

	return fmt.Sprintf("## %s\n**Severity**: %s\n\n%s", f.Type, strings.Title(strings.ToLower(f.Severity)), description)
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
	fmt.Printf("[EVENT] [%s]: %s - %s\n", event.ID[:8], event.Type, event.Content[:min(30, len(event.Content))])
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
		Content:  "[STATS] Queue Stats Updated",
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
		// Previously missing entries
		"blindoracle":         "blindoracle",
		"Blind Oracle":        "blindoracle",
		"cachepoisoning":      "cachepoisoning",
		"Cache Poisoning":     "cachepoisoning",
		"cors":                "cors",
		"CORS":                "cors",
		"deserialization":     "deserialization",
		"Deserialization":     "deserialization",
		"graphql":             "graphql",
		"GraphQL":             "graphql",
		"hostheader":          "hostheader",
		"Host Header":         "hostheader",
		"Host Header Injection": "hostheader",
		"k8s":                 "k8s",
		"K8s":                 "k8s",
		"Kubernetes":          "k8s",
		"log4shell":           "log4shell",
		"Log4Shell":           "log4shell",
		"Log4j":               "log4shell",
		"oauth":               "oauth",
		"OAuth":               "oauth",
		"postexploit":         "postexploit",
		"Post Exploit":        "postexploit",
		"Post-Exploitation":   "postexploit",
		"racecondition":       "racecondition",
		"Race Condition":      "racecondition",
		"s3enum":              "s3enum",
		"S3 Enum":             "s3enum",
		"Bucket Enum":         "s3enum",
		"saml":                "saml",
		"SAML":                "saml",
		"secondorder":         "secondorder",
		"Second Order":        "secondorder",
		"Second-Order":        "secondorder",
		"smuggling":           "smuggling",
		"Smuggling":           "smuggling",
		"HTTP Smuggling":      "smuggling",
		"Request Smuggling":   "smuggling",
		"ssti":                "ssti",
		"SSTI":                "ssti",
		"Server-Side Template Injection": "ssti",
		"websocket":           "websocket",
		"WebSocket":           "websocket",
	}
	if q, ok := nameMap[name]; ok {
		return q
	}
	// Last-resort: try lowercase direct match against registered agents
	lower := strings.ToLower(name)
	if _, ok := nameMap[lower]; ok {
		return nameMap[lower]
	}
	return "xss" // Fallback
}

func normalizeBrainNote(note string) string {
	trimmed := strings.TrimSpace(note)
	if trimmed == "" {
		return ""
	}

	normalized := strings.Join(strings.Fields(trimmed), " ")
	lower := strings.ToLower(normalized)
	rejectFragments := []string{
		"http://w3c//dtd",
		"https://w3c//dtd",
		"//w3c//dtd",
		"<!doctype",
		"<!entity",
		"<?xml",
	}
	for _, fragment := range rejectFragments {
		if strings.Contains(lower, fragment) {
			return ""
		}
	}

	if len(normalized) > 320 {
		normalized = normalized[:320]
	}

	return normalized
}

func dispatchFingerprint(spec SwarmAgentSpec, baseTarget string) string {
	target := strings.TrimSpace(spec.Target)
	if target == "" {
		target = extractTargetHint(spec.Context)
	}
	resolved := resolveDispatchTarget(baseTarget, target)
	contextHash := hashDispatchContext(spec.Context)

	return strings.ToLower(strings.Join([]string{
		normalizeSpecialistName(spec.Type),
		strings.TrimSpace(resolved),
		contextHash,
	}, "|"))
}

func hashDispatchContext(context string) string {
	normalized := normalizeBrainNote(context)
	if normalized == "" {
		return ""
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(normalized))
	return fmt.Sprintf("%08x", hasher.Sum32())
}

func isBrowserSpecialist(queueName string) bool {
	switch queueName {
	case "visualcrawler":
		return true
	default:
		return false
	}
}

func filterDispatchSpecs(specs []SwarmAgentSpec, dispatched map[string]struct{}, baseTarget string, browserAvailable bool) []SwarmAgentSpec {
	filtered := make([]SwarmAgentSpec, 0, len(specs))
	seen := make(map[string]struct{}, len(specs))

	for _, spec := range specs {
		if strings.TrimSpace(spec.Type) == "" {
			continue
		}

		queueName := normalizeSpecialistName(spec.Type)
		if !browserAvailable && isBrowserSpecialist(queueName) {
			continue
		}

		fp := dispatchFingerprint(spec, baseTarget)
		if _, exists := seen[fp]; exists {
			continue
		}
		if _, exists := dispatched[fp]; exists {
			continue
		}

		seen[fp] = struct{}{}
		filtered = append(filtered, spec)
	}

	return filtered
}

func buildFallbackAgentSpecs(baseTarget string, brain *Brain) []SwarmAgentSpec {
	var specs []SwarmAgentSpec
	seen := make(map[string]struct{})

	addSpec := func(spec SwarmAgentSpec) {
		spec.Type = strings.TrimSpace(spec.Type)
		if spec.Type == "" {
			return
		}
		if spec.Priority == "" {
			spec.Priority = "medium"
		}
		if spec.Target == "" {
			spec.Target = baseTarget
		}
		fp := strings.ToLower(strings.Join([]string{
			normalizeSpecialistName(spec.Type),
			spec.Target,
		}, "|"))
		if _, exists := seen[fp]; exists {
			return
		}
		seen[fp] = struct{}{}
		specs = append(specs, spec)
	}

	for _, finding := range brain.Findings {
		if finding == nil {
			continue
		}
		addSpec(SwarmAgentSpec{
			Type:     finding.Type,
			Target:   finding.URL,
			Context:  fmt.Sprintf("Confirmed evidence already exists for %s at %s; validate and expand proof.", finding.Type, finding.URL),
			Priority: "high",
		})
	}

	combinedNotes := append([]string{}, brain.Leads...)
	if strings.TrimSpace(brain.PivotContext) != "" {
		combinedNotes = append(combinedNotes, brain.PivotContext)
	}

	for _, raw := range combinedNotes {
		note := strings.ToLower(normalizeBrainNote(raw))
		if note == "" {
			continue
		}

		switch {
		case strings.Contains(note, "login"), strings.Contains(note, "auth"), strings.Contains(note, "credential"):
			addSpec(SwarmAgentSpec{Type: "Auth Discovery", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "/api"), strings.Contains(note, "json"), strings.Contains(note, "graphql"):
			addSpec(SwarmAgentSpec{Type: "API Security", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "upload"):
			addSpec(SwarmAgentSpec{Type: "File Upload", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "xss"), strings.Contains(note, "script"), strings.Contains(note, "dom"):
			addSpec(SwarmAgentSpec{Type: "XSS", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "sqli"), strings.Contains(note, "sql"), strings.Contains(note, "database"):
			addSpec(SwarmAgentSpec{Type: "SQLi", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "ssrf"), strings.Contains(note, "metadata"), strings.Contains(note, "callback"):
			addSpec(SwarmAgentSpec{Type: "SSRF", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "include"), strings.Contains(note, "passwd"), strings.Contains(note, "traversal"), strings.Contains(note, "lfi"):
			addSpec(SwarmAgentSpec{Type: "LFI", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "exec"), strings.Contains(note, "command"), strings.Contains(note, "shell"), strings.Contains(note, "rce"):
			addSpec(SwarmAgentSpec{Type: "RCE", Target: extractTargetHint(raw), Context: raw, Priority: "high"})
		case strings.Contains(note, "idor"), strings.Contains(note, "object id"), strings.Contains(note, "profile"), strings.Contains(note, "account"):
			addSpec(SwarmAgentSpec{Type: "IDOR", Target: extractTargetHint(raw), Context: raw, Priority: "medium"})
		case strings.Contains(note, "spa"), strings.Contains(note, "react"), strings.Contains(note, "vue"), strings.Contains(note, "angular"):
			addSpec(SwarmAgentSpec{Type: "Visual Crawler", Target: extractTargetHint(raw), Context: raw, Priority: "medium"})
		}
	}

	if len(specs) == 0 {
		addSpec(SwarmAgentSpec{
			Type:     "Auth Discovery",
			Target:   baseTarget,
			Context:  "Planner fallback: prioritize authenticated paths and session handling before broad rediscovery.",
			Priority: "high",
		})
		addSpec(SwarmAgentSpec{
			Type:     "API Security",
			Target:   baseTarget,
			Context:  "Planner fallback: inspect discovered routes for API and parameter attack surface.",
			Priority: "medium",
		})
		addSpec(SwarmAgentSpec{
			Type:     "URLMaster",
			Target:   baseTarget,
			Context:  "Planner fallback: consolidate known routes instead of restarting full recon.",
			Priority: "medium",
		})
	}

	return specs
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

// validateScanTarget rejects private/loopback/link-local targets to prevent SSRF misuse.
func validateScanTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("target URL has no host")
	}
	// Resolve hostname to IPs
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		// DNS failure is non-fatal — target may be unreachable but we still allow it.
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("target %s resolves to reserved/loopback address %s — refusing scan", target, addr)
		}
		// Block RFC-1918 private ranges
		for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7"} {
			_, privateNet, _ := net.ParseCIDR(cidr)
			if privateNet != nil && privateNet.Contains(ip) {
				return fmt.Errorf("target %s resolves to private address %s — refusing scan (configure allowlist to override)", target, addr)
			}
		}
	}
	return nil
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
