// Package plugins provides a module system for community-extensible
// pentest operation profiles. Plugins are auto-discovered at startup
// from the plugins/ directory.
//
// Plugin structure:
//
//	plugins/
//	  your_module/
//	    execution_prompt.md    # How to approach this domain
//	    report_prompt.md       # How to document findings
//	    module.yaml            # Configuration
//	    tools/                 # Optional custom tool scripts
//	      your_tool.py
package plugins

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ModuleConfig is the configuration for a plugin module.
type ModuleConfig struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Author      string   `yaml:"author"`
	Tags        []string `yaml:"tags"`
	Targets     []string `yaml:"targets"` // tech stack patterns this module is suited for
	Timeout     int      `yaml:"timeout"` // max execution time in seconds
	Priority    int      `yaml:"priority"` // higher = preferred
	Enabled     bool     `yaml:"enabled"`
}

// Module represents a loaded plugin module.
type Module struct {
	Config          ModuleConfig `json:"config"`
	Path            string       `json:"path"`
	ExecutionPrompt string       `json:"execution_prompt"`
	ReportPrompt    string       `json:"report_prompt"`
	ToolScripts     []string     `json:"tool_scripts"`
}

// Registry holds all loaded plugin modules.
type Registry struct {
	modules map[string]*Module
	baseDir string
}

// NewRegistry creates a plugin registry and discovers modules from the base directory.
func NewRegistry(baseDir string) *Registry {
	r := &Registry{
		modules: make(map[string]*Module),
		baseDir: baseDir,
	}
	return r
}

// Discover scans the base directory for plugin modules.
func (r *Registry) Discover() error {
	if r.baseDir == "" {
		return nil
	}

	entries, err := os.ReadDir(r.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[plugins] No plugins directory at %s", r.baseDir)
			return nil
		}
		return fmt.Errorf("failed to read plugins dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		modulePath := filepath.Join(r.baseDir, entry.Name())
		module, err := r.loadModule(modulePath)
		if err != nil {
			log.Printf("[plugins] Skipping %s: %v", entry.Name(), err)
			continue
		}

		if !module.Config.Enabled {
			log.Printf("[plugins] Module %s is disabled, skipping", module.Config.Name)
			continue
		}

		r.modules[module.Config.Name] = module
		log.Printf("[plugins] Loaded module: %s v%s (%s)", module.Config.Name, module.Config.Version, module.Config.Description)
	}

	log.Printf("[plugins] Discovered %d modules from %s", len(r.modules), r.baseDir)
	return nil
}

// loadModule reads a plugin module from a directory.
func (r *Registry) loadModule(path string) (*Module, error) {
	configPath := filepath.Join(path, "module.yaml")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("missing module.yaml: %w", err)
	}

	var config ModuleConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("invalid module.yaml: %w", err)
	}

	if config.Name == "" {
		config.Name = filepath.Base(path)
	}

	module := &Module{
		Config: config,
		Path:   path,
	}

	// Load execution prompt
	if data, err := os.ReadFile(filepath.Join(path, "execution_prompt.md")); err == nil {
		module.ExecutionPrompt = string(data)
	}

	// Load report prompt
	if data, err := os.ReadFile(filepath.Join(path, "report_prompt.md")); err == nil {
		module.ReportPrompt = string(data)
	}

	// Discover tool scripts
	toolsDir := filepath.Join(path, "tools")
	if entries, err := os.ReadDir(toolsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				module.ToolScripts = append(module.ToolScripts, filepath.Join(toolsDir, entry.Name()))
			}
		}
	}

	return module, nil
}

// GetModule returns a loaded module by name.
func (r *Registry) GetModule(name string) (*Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

// GetModules returns all loaded modules.
func (r *Registry) GetModules() []*Module {
	result := make([]*Module, 0, len(r.modules))
	for _, m := range r.modules {
		result = append(result, m)
	}
	return result
}

// FindModulesForTech returns modules suited for a given tech stack.
func (r *Registry) FindModulesForTech(techStack string) []*Module {
	lower := strings.ToLower(techStack)
	var matches []*Module
	for _, m := range r.modules {
		for _, target := range m.Config.Targets {
			if strings.Contains(lower, strings.ToLower(target)) {
				matches = append(matches, m)
				break
			}
		}
	}
	return matches
}

// EnableModule enables a module by name.
func (r *Registry) EnableModule(name string) error {
	m, ok := r.modules[name]
	if !ok {
		return fmt.Errorf("module %s not found", name)
	}
	m.Config.Enabled = true
	return nil
}

// DisableModule disables a module by name.
func (r *Registry) DisableModule(name string) error {
	m, ok := r.modules[name]
	if !ok {
		return fmt.Errorf("module %s not found", name)
	}
	m.Config.Enabled = false
	return nil
}
