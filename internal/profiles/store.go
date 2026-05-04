package profiles

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AgentConfig specifies one agent's participation in a profile.
type AgentConfig struct {
	ID      string                 `json:"id"`
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config,omitempty"`
}

// Profile is a reusable scan configuration template.
type Profile struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Category    string        `json:"category"` // web|api|cloud|devsecops|compliance|custom
	Icon        string        `json:"icon"`     // lucide icon name hint
	Color       string        `json:"color"`    // hex
	Agents      []AgentConfig `json:"agents"`
	Tags        []string      `json:"tags"`
	Builtin     bool          `json:"builtin"`
	UseCount    int           `json:"use_count"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// Store manages profiles in memory, seeded with built-in templates.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
}

// NewStore creates a store pre-populated with built-in profiles.
func NewStore() *Store {
	st := &Store{profiles: make(map[string]*Profile)}
	for _, p := range builtinProfiles() {
		cp := p
		st.profiles[cp.ID] = &cp
	}
	return st
}

// List returns all profiles, optionally filtered by category.
func (st *Store) List(category string) []*Profile {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*Profile, 0, len(st.profiles))
	for _, p := range st.profiles {
		if category != "" && p.Category != category {
			continue
		}
		cp := *p
		out = append(out, &cp)
	}
	return out
}

// Get retrieves a profile by ID.
func (st *Store) Get(id string) (*Profile, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	p, ok := st.profiles[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Create adds a new custom profile.
func (st *Store) Create(name, description, category, color string, agents []AgentConfig, tags []string) (*Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	now := time.Now()
	p := &Profile{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Category:    category,
		Color:       color,
		Icon:        "Settings",
		Agents:      agents,
		Tags:        tags,
		Builtin:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	st.mu.Lock()
	st.profiles[p.ID] = p
	st.mu.Unlock()
	return p, nil
}

// Update modifies a custom profile (built-in profiles are immutable).
func (st *Store) Update(id, name, description, color string, agents []AgentConfig, tags []string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.profiles[id]
	if !ok {
		return fmt.Errorf("profile %s not found", id)
	}
	if p.Builtin {
		return fmt.Errorf("built-in profiles cannot be modified")
	}
	p.Name = name
	p.Description = description
	p.Color = color
	p.Agents = agents
	p.Tags = tags
	p.UpdatedAt = time.Now()
	return nil
}

// Delete removes a custom profile.
func (st *Store) Delete(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.profiles[id]
	if !ok {
		return fmt.Errorf("profile %s not found", id)
	}
	if p.Builtin {
		return fmt.Errorf("built-in profiles cannot be deleted")
	}
	delete(st.profiles, id)
	return nil
}

// Clone creates a copy of any profile (including built-in).
func (st *Store) Clone(id string) (*Profile, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	src, ok := st.profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile %s not found", id)
	}
	now := time.Now()
	cp := *src
	cp.ID = uuid.New().String()
	cp.Name = "Copy of " + src.Name
	cp.Builtin = false
	cp.UseCount = 0
	cp.CreatedAt = now
	cp.UpdatedAt = now
	st.profiles[cp.ID] = &cp
	out := cp
	return &out, nil
}

// IncrementUseCount records a profile being used for a scan.
func (st *Store) IncrementUseCount(id string) {
	st.mu.Lock()
	if p, ok := st.profiles[id]; ok {
		p.UseCount++
	}
	st.mu.Unlock()
}
