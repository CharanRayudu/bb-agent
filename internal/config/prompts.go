package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Prompts holds all externalized agent prompts loaded from prompts.yaml
type Prompts struct {
	PhaseTemplate string            `yaml:"phase_template"`
	Phases        PhasePrompts      `yaml:"phases"`
	SwarmAgents   map[string]string `yaml:"swarm_agents"`
	Tooling       map[string]string `yaml:"tooling"`
}

// PhasePrompts stores instructions for each orchestration phase
type PhasePrompts struct {
	Recon        string `yaml:"recon"`
	Planner      string `yaml:"planner"`
	Swarm        string `yaml:"swarm"`
	PocGenerator string `yaml:"poc_generator"`
}

// LoadPrompts reads and parses a prompts YAML file
func LoadPrompts(path string) (*Prompts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read prompts file %s: %w", path, err)
	}

	var p Prompts
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse prompts file %s: %w", path, err)
	}

	// Count loaded prompts for logging
	count := 0
	if p.Phases.Recon != "" {
		count++
	}
	if p.Phases.Planner != "" {
		count++
	}
	if p.Phases.Swarm != "" {
		count++
	}
	if p.Phases.PocGenerator != "" {
		count++
	}
	log.Printf("[PROMPTS] Loaded %d phase prompts and %d tooling entries from %s", count, len(p.Tooling), path)

	return &p, nil
}

// BuildPhasePrompt renders the master phase template with the given parameters
func (p *Prompts) BuildPhasePrompt(phase, instructions, target, userPrompt, history string) string {
	result := p.PhaseTemplate
	result = strings.ReplaceAll(result, "{{phase}}", phase)
	result = strings.ReplaceAll(result, "{{instructions}}", instructions)
	result = strings.ReplaceAll(result, "{{target}}", target)
	result = strings.ReplaceAll(result, "{{user_prompt}}", userPrompt)
	result = strings.ReplaceAll(result, "{{history}}", history)
	return result
}

// RenderSwarmPrompt renders the swarm phase prompt with agent-specific variables
func (p *Prompts) RenderSwarmPrompt(agentType, agentContext, target, userPrompt string) string {
	tooling := p.GetToolingInstruction(agentType)

	instructions := p.Phases.Swarm
	if specialized, ok := p.SwarmAgents[agentType]; ok {
		instructions = specialized
	}

	instructions = strings.ReplaceAll(instructions, "{{agent_type}}", agentType)
	instructions = strings.ReplaceAll(instructions, "{{tooling}}", tooling)
	instructions = strings.ReplaceAll(instructions, "{{agent_context}}", agentContext)

	return p.BuildPhasePrompt("SWARM AGENT", instructions, target, userPrompt, "")
}

// GetToolingInstruction returns the tool recommendation for a vulnerability type
func (p *Prompts) GetToolingInstruction(vulnType string) string {
	if instr, ok := p.Tooling[vulnType]; ok {
		return instr
	}
	if def, ok := p.Tooling["default"]; ok {
		return def
	}
	return "Use best available tools (ffuf, nuclei)."
}
