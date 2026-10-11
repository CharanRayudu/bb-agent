package agent

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ObserverVerdict is a control decision from the independent execution observer.
type ObserverVerdict string

const (
	ObserverContinue ObserverVerdict = "continue"
	ObserverReplan   ObserverVerdict = "replan"
	ObserverAbort    ObserverVerdict = "abort"
)

// ExecutionHealth is a compact snapshot for the dashboard and reports.
type ExecutionHealth struct {
	ToolCalls         int             `json:"tool_calls"`
	SecurityToolRuns  int             `json:"security_tool_runs"`
	ToolFailures      int             `json:"tool_failures"`
	RepeatedFailures  map[string]int  `json:"repeated_failures,omitempty"`
	LLMErrors         int             `json:"llm_errors"`
	LastProgressAgeMS int64           `json:"last_progress_age_ms"`
	Verdict           ObserverVerdict `json:"verdict"`
	Reason            string          `json:"reason,omitempty"`
}

// ExecutionObserver watches orchestrator progress without owning planning or tools.
// Inspired by LuaN1aoAgent / BreachWeave supervisor separation, but implemented
// as a thin Go component over Mirage events and counters.
type ExecutionObserver struct {
	mu sync.Mutex

	toolCalls        map[string]int
	toolFailures     map[string]int
	securityToolRuns int
	llmErrors        int
	lastProgress     time.Time
	replanRequested  bool
	abortReason      string
}

func NewExecutionObserver() *ExecutionObserver {
	return &ExecutionObserver{
		toolCalls:    make(map[string]int),
		toolFailures: make(map[string]int),
		lastProgress: time.Now(),
	}
}

func (o *ExecutionObserver) NoteLLMError() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.llmErrors++
}

func (o *ExecutionObserver) NoteTool(name string, failed bool) {
	if o == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.toolCalls[name]++
	o.lastProgress = time.Now()
	if isObservedSecurityTool(name) {
		o.securityToolRuns++
	}
	if failed {
		o.toolFailures[name]++
		if o.toolFailures[name] >= 3 {
			o.replanRequested = true
		}
		if o.toolFailures[name] >= 5 {
			o.abortReason = fmt.Sprintf("tool %s failed %d times", name, o.toolFailures[name])
		}
	}
}

func (o *ExecutionObserver) RequestReplan(reason string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.replanRequested = true
	if reason != "" && o.abortReason == "" {
		o.abortReason = reason
	}
}

func (o *ExecutionObserver) ConsumeReplanRequest() (bool, string) {
	if o == nil {
		return false, ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.replanRequested {
		return false, ""
	}
	o.replanRequested = false
	reason := o.abortReason
	if reason == "" {
		reason = "observer requested replanning after repeated failures"
	}
	return true, reason
}

func (o *ExecutionObserver) Health() ExecutionHealth {
	if o == nil {
		return ExecutionHealth{Verdict: ObserverContinue}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	failures := 0
	repeated := map[string]int{}
	for name, n := range o.toolFailures {
		failures += n
		if n >= 2 {
			repeated[name] = n
		}
	}
	calls := 0
	for _, n := range o.toolCalls {
		calls += n
	}
	verdict := ObserverContinue
	reason := ""
	if o.abortReason != "" && o.toolFailuresHaveHardStopLocked() {
		verdict = ObserverAbort
		reason = o.abortReason
	} else if o.replanRequested {
		verdict = ObserverReplan
		reason = "repeated tool failures"
	}
	age := time.Since(o.lastProgress).Milliseconds()
	return ExecutionHealth{
		ToolCalls:         calls,
		SecurityToolRuns:  o.securityToolRuns,
		ToolFailures:      failures,
		RepeatedFailures:  repeated,
		LLMErrors:         o.llmErrors,
		LastProgressAgeMS: age,
		Verdict:           verdict,
		Reason:            reason,
	}
}

func (o *ExecutionObserver) toolFailuresHaveHardStopLocked() bool {
	for _, n := range o.toolFailures {
		if n >= 5 {
			return true
		}
	}
	return o.abortReason != "" && strings.Contains(o.abortReason, "failed")
}

// IncompleteAssessment refuses a green completion when nothing was actually tested.
func (o *ExecutionObserver) IncompleteAssessment(findings, workspaceArtifacts, evidencePacks int) error {
	if o == nil {
		return nil
	}
	health := o.Health()
	if health.SecurityToolRuns > 0 || findings > 0 || workspaceArtifacts > 0 || evidencePacks > 0 {
		return nil
	}
	if health.LLMErrors > 0 {
		return fmt.Errorf("generative model errors occurred and no scanner evidence was produced")
	}
	return fmt.Errorf("no security tools, findings, or evidence were produced; refusing successful completion")
}

func isObservedSecurityTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "run_security_tool", "execute_command",
		"nmap", "nuclei", "ffuf", "sqlmap", "curl", "httpx", "katana",
		"gobuster", "feroxbuster", "dalfox", "nikto", "wpscan":
		return true
	default:
		return false
	}
}
