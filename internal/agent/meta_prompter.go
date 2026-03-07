package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// PromptRegion marks a section of a prompt as protected or optimizable.
type PromptRegion struct {
	Tag       string `json:"tag"`
	Content   string `json:"content"`
	Protected bool   `json:"protected"` // true = never modify
}

// MetaPrompter enables agents to rewrite their own execution guidance
// mid-operation based on what they've learned. Inspired by Cyber-AutoAgent.
//
// Protected regions (marked with XML tags) preserve critical logic.
// Optimizable sections evolve based on execution feedback.
type MetaPrompter struct {
	llmProvider    llm.Provider
	mu             sync.RWMutex
	originalPrompt string
	workingPrompt  string
	revisionCount  int
	revisionLog    []PromptRevision
	stepInterval   int // revise every N steps
}

// PromptRevision records a change made to the working prompt.
type PromptRevision struct {
	Step     int    `json:"step"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Reason   string `json:"reason"`
	Revision int    `json:"revision"`
}

// NewMetaPrompter creates a new meta-prompter for self-evolving guidance.
func NewMetaPrompter(provider llm.Provider, stepInterval int) *MetaPrompter {
	if stepInterval <= 0 {
		stepInterval = 20 // default: revise every 20 steps
	}
	return &MetaPrompter{
		llmProvider:  provider,
		revisionLog:  make([]PromptRevision, 0),
		stepInterval: stepInterval,
	}
}

// Initialize sets the base prompt that will be evolved.
func (mp *MetaPrompter) Initialize(prompt string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.originalPrompt = prompt
	mp.workingPrompt = prompt
	mp.revisionCount = 0
	mp.revisionLog = make([]PromptRevision, 0)
}

// GetPrompt returns the current (potentially evolved) working prompt.
func (mp *MetaPrompter) GetPrompt() string {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.workingPrompt
}

// ShouldRevise returns true if it's time for a prompt revision.
func (mp *MetaPrompter) ShouldRevise(currentStep int) bool {
	return currentStep > 0 && currentStep%mp.stepInterval == 0
}

// Revise analyzes execution history and rewrites the optimizable sections
// of the working prompt. Protected regions (between <protected> tags) are
// preserved unchanged.
func (mp *MetaPrompter) Revise(ctx context.Context, currentStep int, executionSummary string, brain *Brain) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	protected, optimizable := mp.splitRegions(mp.workingPrompt)

	prompt := fmt.Sprintf(`You are a Prompt Optimizer for an autonomous penetration testing agent.

The agent has been running for %d steps. Based on the execution history below,
rewrite the OPTIMIZABLE sections of the agent's execution guidance to improve
effectiveness. DO NOT modify the PROTECTED sections.

PROTECTED SECTIONS (do NOT change):
%s

CURRENT OPTIMIZABLE GUIDANCE:
%s

EXECUTION SUMMARY (what worked and what didn't):
%s

BRAIN STATE:
- Leads: %d
- Findings: %d  
- Exclusions (dead ends): %d

INSTRUCTIONS:
1. Remove approaches that have been failing
2. Emphasize techniques that have shown promise
3. Add specific tactical adjustments based on what was learned
4. Keep the guidance concise and actionable

Output ONLY the rewritten optimizable guidance section. No explanation.`, currentStep, protected, optimizable, truncate(executionSummary, 3000),
		len(brain.Leads), len(brain.Findings), len(brain.Exclusions))

	resp, err := mp.llmProvider.Complete(ctx, llm.CompletionRequest{
		Messages: []models.ChatMessage{
			{Role: "system", Content: "You are a prompt engineering specialist. Output only the revised prompt text."},
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return fmt.Errorf("meta-prompt revision failed: %w", err)
	}

	newOptimizable := strings.TrimSpace(resp.Content)
	if newOptimizable == "" || len(newOptimizable) < 50 {
		return fmt.Errorf("revision produced empty or too-short result")
	}

	// Record the revision
	mp.revisionLog = append(mp.revisionLog, PromptRevision{
		Step:     currentStep,
		Before:   truncate(optimizable, 500),
		After:    truncate(newOptimizable, 500),
		Reason:   fmt.Sprintf("Auto-revision at step %d", currentStep),
		Revision: mp.revisionCount + 1,
	})

	// Reconstruct the working prompt with protected sections intact
	mp.workingPrompt = mp.mergeRegions(protected, newOptimizable)
	mp.revisionCount++

	log.Printf("[meta-prompter] Revised prompt (revision %d at step %d)", mp.revisionCount, currentStep)
	return nil
}

// GetRevisionLog returns the history of prompt revisions.
func (mp *MetaPrompter) GetRevisionLog() []PromptRevision {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	out := make([]PromptRevision, len(mp.revisionLog))
	copy(out, mp.revisionLog)
	return out
}

// RevisionCount returns how many times the prompt has been revised.
func (mp *MetaPrompter) RevisionCount() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.revisionCount
}

// splitRegions separates the prompt into protected and optimizable parts.
// Protected regions are enclosed in <protected>...</protected> tags.
func (mp *MetaPrompter) splitRegions(prompt string) (protected, optimizable string) {
	var protectedParts, optimizableParts []string
	remaining := prompt

	for {
		startTag := "<protected>"
		endTag := "</protected>"

		startIdx := strings.Index(remaining, startTag)
		if startIdx == -1 {
			optimizableParts = append(optimizableParts, remaining)
			break
		}

		// Everything before the tag is optimizable
		if startIdx > 0 {
			optimizableParts = append(optimizableParts, remaining[:startIdx])
		}

		endIdx := strings.Index(remaining[startIdx:], endTag)
		if endIdx == -1 {
			// No closing tag, treat the rest as protected
			protectedParts = append(protectedParts, remaining[startIdx+len(startTag):])
			break
		}

		protectedContent := remaining[startIdx+len(startTag) : startIdx+endIdx]
		protectedParts = append(protectedParts, protectedContent)
		remaining = remaining[startIdx+endIdx+len(endTag):]
	}

	protected = strings.Join(protectedParts, "\n---\n")
	optimizable = strings.Join(optimizableParts, "\n")
	return
}

// mergeRegions reassembles the prompt with protected sections intact
// and the new optimizable content.
func (mp *MetaPrompter) mergeRegions(protected, newOptimizable string) string {
	// If original had no protected tags, just return the new content
	// prepended with the protected sections.
	if !strings.Contains(mp.originalPrompt, "<protected>") {
		return newOptimizable
	}

	// Reconstruct: put protected sections back in their original positions
	result := mp.originalPrompt
	protectedParts := strings.Split(protected, "\n---\n")
	optimizableParts := strings.Split(newOptimizable, "\n")

	// Replace optimizable sections between protected blocks
	for _, pp := range protectedParts {
		placeholder := pp
		if strings.Contains(result, placeholder) {
			result = strings.Replace(result, placeholder, placeholder, 1)
		}
	}

	// If we can't do smart merging, fall back to prepending protected + new content
	_ = optimizableParts
	if len(protectedParts) > 0 {
		var b strings.Builder
		for _, pp := range protectedParts {
			b.WriteString("<protected>\n")
			b.WriteString(pp)
			b.WriteString("\n</protected>\n\n")
		}
		b.WriteString(newOptimizable)
		return b.String()
	}

	return newOptimizable
}
