// Package monitoring implements continuous attack surface monitoring —
// scheduled rescans, finding delta detection, and multi-channel alerting.
//
// Architecture:
//   - Monitor: a named watch on a target with a cron schedule + alert channels
//   - Baseline: hash-fingerprinted snapshot of a target's findings
//   - Delta: new / resolved / regressed findings between two scans
//   - AlertChannel: Slack / PagerDuty / Teams / generic webhook dispatcher
package monitoring

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MonitorStatus describes whether a monitor is active.
type MonitorStatus string

const (
	StatusActive MonitorStatus = "active"
	StatusPaused MonitorStatus = "paused"
	StatusError  MonitorStatus = "error"
)

// Monitor watches a target and triggers rescans on a cron schedule.
type Monitor struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	Target           string        `json:"target"`
	Profile          string        `json:"profile"`        // scan profile (full, quick, stealth)
	CronExpr         string        `json:"cron_expr"`      // "30 6 * * *" = 06:30 daily
	AlertChannels    []string      `json:"alert_channels"` // IDs of alert channels to notify
	Status           MonitorStatus `json:"status"`
	CreatedAt        time.Time     `json:"created_at"`
	LastScanAt       *time.Time    `json:"last_scan_at,omitempty"`
	LastDeltaAt      *time.Time    `json:"last_delta_at,omitempty"`
	BaselineAt       *time.Time    `json:"baseline_at,omitempty"`
	FindingCount     int           `json:"finding_count"` // current known count
	NewSinceBaseline int           `json:"new_since_baseline"`
	SchedulerID      string        `json:"scheduler_id,omitempty"` // ID in agent.Scheduler
}

// Store is the in-memory store for monitors, baselines, and deltas.
type Store struct {
	mu        sync.RWMutex
	monitors  map[string]*Monitor
	baselines map[string]Baseline // monitorID → baseline
	deltas    map[string][]Delta  // monitorID → []Delta (most recent first)
	channels  map[string]*AlertChannel
}

// NewStore creates an empty monitoring store.
func NewStore() *Store {
	return &Store{
		monitors:  map[string]*Monitor{},
		baselines: map[string]Baseline{},
		deltas:    map[string][]Delta{},
		channels:  map[string]*AlertChannel{},
	}
}

// AddMonitor creates a new monitor.
func (st *Store) AddMonitor(name, target, profile, cronExpr string, alertChannels []string) (*Monitor, error) {
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if name == "" {
		name = target
	}
	if cronExpr == "" {
		cronExpr = "0 6 * * *" // daily at 06:00
	}

	m := &Monitor{
		ID:            uuid.New().String(),
		Name:          name,
		Target:        target,
		Profile:       profile,
		CronExpr:      cronExpr,
		AlertChannels: alertChannels,
		Status:        StatusActive,
		CreatedAt:     time.Now(),
	}

	st.mu.Lock()
	st.monitors[m.ID] = m
	st.mu.Unlock()
	return m, nil
}

// GetMonitor returns a monitor by ID.
func (st *Store) GetMonitor(id string) (*Monitor, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	m, ok := st.monitors[id]
	if !ok {
		return nil, false
	}
	cp := *m
	return &cp, true
}

// ListMonitors returns all monitors.
func (st *Store) ListMonitors() []*Monitor {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*Monitor, 0, len(st.monitors))
	for _, m := range st.monitors {
		cp := *m
		out = append(out, &cp)
	}
	return out
}

// UpdateMonitor updates mutable fields of a monitor.
func (st *Store) UpdateMonitor(id, name, profile, cronExpr string, alertChannels []string, status MonitorStatus) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	m, ok := st.monitors[id]
	if !ok {
		return fmt.Errorf("monitor %s not found", id)
	}
	if name != "" {
		m.Name = name
	}
	if profile != "" {
		m.Profile = profile
	}
	if cronExpr != "" {
		m.CronExpr = cronExpr
	}
	if alertChannels != nil {
		m.AlertChannels = alertChannels
	}
	if status != "" {
		m.Status = status
	}
	return nil
}

// DeleteMonitor removes a monitor.
func (st *Store) DeleteMonitor(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.monitors[id]; !ok {
		return fmt.Errorf("monitor %s not found", id)
	}
	delete(st.monitors, id)
	delete(st.baselines, id)
	delete(st.deltas, id)
	return nil
}

// SetBaseline stores a baseline snapshot for a monitor.
func (st *Store) SetBaseline(monitorID string, bl Baseline) {
	now := time.Now()
	st.mu.Lock()
	st.baselines[monitorID] = bl
	if m, ok := st.monitors[monitorID]; ok {
		m.BaselineAt = &now
		m.FindingCount = len(bl.Fingerprints)
		m.NewSinceBaseline = 0
	}
	st.mu.Unlock()
}

// GetBaseline returns the baseline for a monitor.
func (st *Store) GetBaseline(monitorID string) (Baseline, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	bl, ok := st.baselines[monitorID]
	return bl, ok
}

// AppendDelta records a new delta for a monitor and updates monitor stats.
func (st *Store) AppendDelta(monitorID string, d Delta) {
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()

	// Keep last 50 deltas per monitor
	existing := st.deltas[monitorID]
	updated := append([]Delta{d}, existing...)
	if len(updated) > 50 {
		updated = updated[:50]
	}
	st.deltas[monitorID] = updated

	if m, ok := st.monitors[monitorID]; ok {
		m.LastDeltaAt = &now
		m.NewSinceBaseline += len(d.NewFindings)
	}
}

// GetDeltas returns the delta history for a monitor.
func (st *Store) GetDeltas(monitorID string) []Delta {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]Delta, len(st.deltas[monitorID]))
	copy(out, st.deltas[monitorID])
	return out
}

// MarkScanned updates LastScanAt for a monitor.
func (st *Store) MarkScanned(monitorID string) {
	now := time.Now()
	st.mu.Lock()
	if m, ok := st.monitors[monitorID]; ok {
		m.LastScanAt = &now
	}
	st.mu.Unlock()
}

// SetSchedulerID stores the scheduler job ID on a monitor.
func (st *Store) SetSchedulerID(monitorID, schedulerID string) {
	st.mu.Lock()
	if m, ok := st.monitors[monitorID]; ok {
		m.SchedulerID = schedulerID
	}
	st.mu.Unlock()
}

// ── Alert channels ────────────────────────────────────────────────────────────

// ChannelType identifies an alert provider.
type ChannelType string

const (
	ChannelSlack     ChannelType = "slack"
	ChannelPagerDuty ChannelType = "pagerduty"
	ChannelTeams     ChannelType = "teams"
	ChannelWebhook   ChannelType = "webhook"
)

// AlertChannel defines a notification destination.
type AlertChannel struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        ChannelType       `json:"type"`
	URL         string            `json:"url"`    // webhook URL
	Config      map[string]string `json:"config"` // type-specific config
	Enabled     bool              `json:"enabled"`
	MinSeverity string            `json:"min_severity"` // only alert at this severity or above
}

// AddChannel registers a new alert channel.
func (st *Store) AddChannel(ch AlertChannel) *AlertChannel {
	if ch.ID == "" {
		ch.ID = uuid.New().String()
	}
	if ch.MinSeverity == "" {
		ch.MinSeverity = "high"
	}
	ch.Enabled = true
	st.mu.Lock()
	st.channels[ch.ID] = &ch
	st.mu.Unlock()
	return &ch
}

// GetChannels returns all registered alert channels.
func (st *Store) GetChannels() []*AlertChannel {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*AlertChannel, 0, len(st.channels))
	for _, ch := range st.channels {
		cp := *ch
		out = append(out, &cp)
	}
	return out
}

// GetChannel returns a channel by ID.
func (st *Store) GetChannel(id string) (*AlertChannel, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	ch, ok := st.channels[id]
	if !ok {
		return nil, false
	}
	cp := *ch
	return &cp, true
}

// DeleteChannel removes an alert channel.
func (st *Store) DeleteChannel(id string) {
	st.mu.Lock()
	delete(st.channels, id)
	st.mu.Unlock()
}
