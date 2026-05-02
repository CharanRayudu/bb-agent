package schedplan

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// CronPresets maps preset tokens to their repeat interval.
var CronPresets = map[string]time.Duration{
	"@hourly":   1 * time.Hour,
	"@every6h":  6 * time.Hour,
	"@every12h": 12 * time.Hour,
	"@daily":    24 * time.Hour,
	"@weekly":   7 * 24 * time.Hour,
	"@monthly":  30 * 24 * time.Hour,
}

// CronLabel maps preset tokens to human-readable labels.
var CronLabel = map[string]string{
	"@hourly":   "Every hour",
	"@every6h":  "Every 6 hours",
	"@every12h": "Every 12 hours",
	"@daily":    "Daily",
	"@weekly":   "Weekly",
	"@monthly":  "Monthly",
}

// Schedule is a recurring automated scan plan.
type Schedule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Target      string     `json:"target"`
	ProfileID   string     `json:"profile_id"`
	ProfileName string     `json:"profile_name"`
	Cron        string     `json:"cron"`
	CronLabel   string     `json:"cron_label"`
	Enabled     bool       `json:"enabled"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	LastStatus  string     `json:"last_status"` // "" | "running" | "ok" | "error"
	NextRun     time.Time  `json:"next_run"`
	RunCount    int        `json:"run_count"`
	CreatedAt   time.Time  `json:"created_at"`
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return "sp_" + hex.EncodeToString(b)
}

// Store is a thread-safe in-memory schedule repository.
type Store struct {
	mu    sync.RWMutex
	items map[string]*Schedule
}

func NewStore() *Store {
	return &Store{items: make(map[string]*Schedule)}
}

func (s *Store) List() []*Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Schedule, 0, len(s.items))
	for _, sc := range s.items {
		cp := *sc
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *Store) Get(id string) (*Schedule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.items[id]
	if !ok {
		return nil, false
	}
	cp := *sc
	return &cp, true
}

func (s *Store) Create(name, target, profileID, profileName, cron string) (*Schedule, error) {
	if name == "" || target == "" || cron == "" {
		return nil, errors.New("name, target, and cron are required")
	}
	interval, ok := CronPresets[cron]
	if !ok {
		return nil, errors.New("unsupported cron expression; use @hourly, @every6h, @every12h, @daily, @weekly, or @monthly")
	}
	now := time.Now()
	sc := &Schedule{
		ID:          newID(),
		Name:        name,
		Target:      target,
		ProfileID:   profileID,
		ProfileName: profileName,
		Cron:        cron,
		CronLabel:   CronLabel[cron],
		Enabled:     true,
		NextRun:     now.Add(interval),
		CreatedAt:   now,
	}
	s.mu.Lock()
	s.items[sc.ID] = sc
	s.mu.Unlock()
	cp := *sc
	return &cp, nil
}

func (s *Store) Update(id, name, target, profileID, profileName, cron string) error {
	interval, ok := CronPresets[cron]
	if !ok {
		return errors.New("unsupported cron expression")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok2 := s.items[id]
	if !ok2 {
		return errors.New("schedule not found")
	}
	sc.Name = name
	sc.Target = target
	sc.ProfileID = profileID
	sc.ProfileName = profileName
	sc.Cron = cron
	sc.CronLabel = CronLabel[cron]
	sc.NextRun = time.Now().Add(interval)
	return nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return errors.New("schedule not found")
	}
	delete(s.items, id)
	return nil
}

// Toggle flips the enabled flag and resets NextRun when enabling.
func (s *Store) Toggle(id string) (*Schedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.items[id]
	if !ok {
		return nil, errors.New("schedule not found")
	}
	sc.Enabled = !sc.Enabled
	if sc.Enabled {
		if interval, ok2 := CronPresets[sc.Cron]; ok2 {
			sc.NextRun = time.Now().Add(interval)
		}
	}
	cp := *sc
	return &cp, nil
}

// Due returns enabled schedules that have passed their NextRun time.
func (s *Store) Due() []*Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []*Schedule
	for _, sc := range s.items {
		if sc.Enabled && now.After(sc.NextRun) {
			cp := *sc
			out = append(out, &cp)
		}
	}
	return out
}

func (s *Store) MarkRunning(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc, ok := s.items[id]; ok {
		sc.LastStatus = "running"
	}
}

func (s *Store) MarkComplete(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.items[id]
	if !ok {
		return
	}
	now := time.Now()
	sc.LastRun = &now
	sc.LastStatus = status
	sc.RunCount++
	if interval, ok2 := CronPresets[sc.Cron]; ok2 {
		sc.NextRun = now.Add(interval)
	}
}
