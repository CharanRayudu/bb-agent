package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

// PlanPhase represents a discrete phase within a cognitive plan.
type PlanPhase struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"` // "pending", "active", "completed", "skipped"
	Criteria string `json:"criteria"`
}

// CognitivePlan is the Planner's structured external memory for a flow.
// Stored outside the LLM context window and retrieved at checkpoints.
type CognitivePlan struct {
	FlowID       uuid.UUID    `json:"flow_id"`
	CurrentPhase int          `json:"current_phase"`
	TotalPhases  int          `json:"total_phases"`
	Phases       []*PlanPhase `json:"phases"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Hypothesis   string       `json:"hypothesis"`
	Objective    string       `json:"objective"`

	// Dead-end tracking: paths the planner has ruled out
	DeadEnds []string `json:"dead_ends,omitempty"`
	// Parallel tasks that can run concurrently
	ParallelGroups [][]int `json:"parallel_groups,omitempty"`
}

// Planner maintains global graph awareness, generates multi-phase plans,
// identifies dead-end paths, and schedules parallelizable tasks.
// It replaces the flat "consolidation" specialist with a cognitive role.
type Planner struct {
	llmProvider llm.Provider
	bus         *EventBus
	memory      *Memory
	mu          sync.RWMutex

	activePlans map[uuid.UUID]*CognitivePlan
	confidence  *ConfidenceEngine
}

// NewPlanner creates a new cognitive Planner.
func NewPlanner(provider llm.Provider, bus *EventBus, memory *Memory) *Planner {
	return &Planner{
		llmProvider: provider,
		bus:         bus,
		memory:      memory,
		activePlans: make(map[uuid.UUID]*CognitivePlan),
		confidence:  NewConfidenceEngine(DefaultConfidenceThresholds()),
	}
}

// CreatePlan generates a structured multi-phase attack plan from recon data.
func (p *Planner) CreatePlan(ctx context.Context, flowID uuid.UUID, target, recon string, brain *Brain) (*CognitivePlan, error) {
	prompt := fmt.Sprintf(`You are the Planner in a P-E-R (Planner-Executor-Reflector) autonomous pentest system.
Analyze the reconnaissance data and brain state below, then create a structured multi-phase attack plan.

TARGET: %s

RECON DATA:
%s

BRAIN STATE:
- Leads: %d discovered
- Findings: %d confirmed
- Exclusions: %d dead ends
- Tech Stack: %s

PLANNING RULES:
1. Convert each real lead into a narrow hypothesis node.
2. Group parallelizable tasks together.
3. Identify potential dead ends from exclusions and mark them.
4. Prioritize attack paths with credible proof potential.
5. Model auth as first-class context.

Output a JSON plan with this structure:
{
  "objective": "one sentence describing what we're trying to achieve",
  "hypothesis": "the primary attack hypothesis",
  "phases": [
    {"id": 1, "title": "Phase title", "status": "pending", "criteria": "completion criteria"},
    ...
  ],
  "parallel_groups": [[1,2], [3]], // phase IDs that can run concurrently
  "dead_ends": ["list of known dead-end paths to avoid"]
}`, target, truncate(recon, 4000), len(brain.Leads), len(brain.Findings),
		len(brain.Exclusions), formatTechStack(brain.Tech))

	resp, err := p.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a strategic penetration testing planner. Output valid JSON only."},
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("planner LLM call failed: %w", err)
	}

	plan := &CognitivePlan{
		FlowID:    flowID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	content := extractJSON(resp.Content)
	if err := json.Unmarshal([]byte(content), plan); err != nil {
		plan.Objective = resp.Content
		plan.Phases = []*PlanPhase{
			{ID: 1, Title: "Reconnaissance & Discovery", Status: "pending", Criteria: "Attack surface mapped"},
			{ID: 2, Title: "Vulnerability Testing", Status: "pending", Criteria: "All leads tested"},
			{ID: 3, Title: "Exploitation & Validation", Status: "pending", Criteria: "Findings confirmed with proof"},
		}
	}
	plan.FlowID = flowID
	plan.TotalPhases = len(plan.Phases)
	if plan.TotalPhases > 0 {
		plan.CurrentPhase = 1
		plan.Phases[0].Status = "active"
	}

	p.mu.Lock()
	p.activePlans[flowID] = plan
	p.mu.Unlock()

	log.Printf("[planner] Created %d-phase plan for flow %s: %s", plan.TotalPhases, flowID.String()[:8], plan.Objective)
	return plan, nil
}

// GetPlan retrieves the active plan for a flow.
func (p *Planner) GetPlan(flowID uuid.UUID) *CognitivePlan {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activePlans[flowID]
}

// AdvancePlan moves the plan to the next phase.
func (p *Planner) AdvancePlan(flowID uuid.UUID, reason string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	plan, ok := p.activePlans[flowID]
	if !ok {
		return fmt.Errorf("no active plan for flow %s", flowID)
	}

	for i, phase := range plan.Phases {
		if phase.Status == "active" {
			phase.Status = "completed"
			if i+1 < len(plan.Phases) {
				plan.Phases[i+1].Status = "active"
				plan.CurrentPhase = plan.Phases[i+1].ID
			}
			break
		}
	}
	plan.UpdatedAt = time.Now()

	log.Printf("[planner] Advanced plan for flow %s to phase %d: %s", flowID.String()[:8], plan.CurrentPhase, reason)
	return nil
}

// MarkDeadEnd records a dead-end path so the planner avoids it.
func (p *Planner) MarkDeadEnd(flowID uuid.UUID, path string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	plan, ok := p.activePlans[flowID]
	if !ok {
		return
	}
	plan.DeadEnds = append(plan.DeadEnds, path)
	plan.UpdatedAt = time.Now()
}

// GenerateDispatchSpecs converts the current plan phase into SwarmAgentSpecs.
func (p *Planner) GenerateDispatchSpecs(ctx context.Context, flowID uuid.UUID, brain *Brain, target string) ([]SwarmAgentSpec, error) {
	plan := p.GetPlan(flowID)
	if plan == nil {
		return nil, fmt.Errorf("no plan for flow %s", flowID)
	}

	var currentPhase *PlanPhase
	for _, phase := range plan.Phases {
		if phase.Status == "active" {
			currentPhase = phase
			break
		}
	}
	if currentPhase == nil {
		return nil, fmt.Errorf("no active phase in plan for flow %s", flowID)
	}

	prompt := fmt.Sprintf(`Based on the current plan phase, generate specialist agent dispatch specs.

ACTIVE PHASE: %s
CRITERIA: %s
OBJECTIVE: %s

BRAIN LEADS (%d):
%s

DEAD ENDS TO AVOID:
%s

Generate a JSON array of specialist specs. Each spec:
{
  "type": "specialist type (e.g., Reflected XSS, Time-based SQLi, SSRF, etc.)",
  "target": "exact endpoint/param",
  "context": "attack-path context",
  "hypothesis": "what this specialist is trying to prove",
  "proof": "proof type required (request_response, browser, timing, oob)",
  "requires_auth": false,
  "priority": "critical|high|medium|low"
}`, currentPhase.Title, currentPhase.Criteria, plan.Objective,
		len(brain.Leads), formatLeads(brain.Leads, 30),
		strings.Join(plan.DeadEnds, "\n"))

	resp, err := p.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a penetration testing dispatcher. Output a valid JSON array only."},
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dispatch generation failed: %w", err)
	}

	var specs []SwarmAgentSpec
	content := extractJSON(resp.Content)
	if err := json.Unmarshal([]byte(content), &specs); err != nil {
		return nil, fmt.Errorf("failed to parse dispatch specs: %w (content: %.200s)", err, content)
	}

	return specs, nil
}

// ShouldReplan checks if the plan needs revision based on new intelligence.
func (p *Planner) ShouldReplan(flowID uuid.UUID, brain *Brain) bool {
	plan := p.GetPlan(flowID)
	if plan == nil {
		return true
	}

	significantNewLeads := 0
	for _, lead := range brain.Leads {
		isNew := true
		for _, de := range plan.DeadEnds {
			if strings.Contains(lead, de) {
				isNew = false
				break
			}
		}
		if isNew {
			significantNewLeads++
		}
	}

	// Replan if pivot discovered or many new leads
	if brain.PivotContext != "" || significantNewLeads > 10 {
		return true
	}

	return false
}

// --- Helpers ---

func formatTechStack(ts *TechStack) string {
	if ts == nil {
		return "unknown"
	}
	return fmt.Sprintf("%s/%s/%s", ts.Lang, ts.Server, ts.DB)
}

func formatLeads(leads []string, limit int) string {
	if len(leads) == 0 {
		return "(none)"
	}
	if len(leads) > limit {
		leads = leads[:limit]
	}
	return strings.Join(leads, "\n")
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Try to find JSON block in markdown code fence
	if idx := strings.Index(s, "```json"); idx >= 0 {
		start := idx + 7
		if end := strings.Index(s[start:], "```"); end >= 0 {
			return strings.TrimSpace(s[start : start+end])
		}
	}
	if idx := strings.Index(s, "```"); idx >= 0 {
		start := idx + 3
		if end := strings.Index(s[start:], "```"); end >= 0 {
			return strings.TrimSpace(s[start : start+end])
		}
	}
	// Try raw JSON
	if start := strings.IndexAny(s, "[{"); start >= 0 {
		return s[start:]
	}
	return s
}
