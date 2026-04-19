package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ScheduledScan holds the configuration for a recurring scan.
type ScheduledScan struct {
	ID       string     `json:"id"`
	Target   string     `json:"target"`
	Profile  string     `json:"profile"`
	CronExpr string     `json:"cron_expr"` // "minute hour * * *"
	LastRun  *time.Time `json:"last_run,omitempty"`
	NextRun  time.Time  `json:"next_run"`
	Enabled  bool       `json:"enabled"`
}

// Scheduler manages scheduled scans using a simple minute/hour cron subset.
type Scheduler struct {
	scans   map[string]*ScheduledScan
	mu      sync.RWMutex
	trigger func(target, profile string)
}

// NewScheduler creates a Scheduler that calls triggerFn to start each scan.
func NewScheduler(triggerFn func(target, profile string)) *Scheduler {
	return &Scheduler{
		scans:   make(map[string]*ScheduledScan),
		trigger: triggerFn,
	}
}

// parseCron parses a "minute hour * * *" expression and returns the next run time.
// Only minute and hour fields are used; the remaining three fields are ignored.
func parseCron(expr string, from time.Time) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("cron expression must have 5 fields, got %d", len(fields))
	}

	minute, err := strconv.Atoi(fields[0])
	if err != nil || minute < 0 || minute > 59 {
		return time.Time{}, fmt.Errorf("invalid minute field %q", fields[0])
	}

	hour, err := strconv.Atoi(fields[1])
	if err != nil || hour < 0 || hour > 23 {
		return time.Time{}, fmt.Errorf("invalid hour field %q", fields[1])
	}

	// Compute next scheduled time at the requested hour:minute on or after `from`.
	candidate := time.Date(from.Year(), from.Month(), from.Day(), hour, minute, 0, 0, from.Location())
	if !candidate.After(from) {
		candidate = candidate.Add(24 * time.Hour)
	}
	return candidate, nil
}

// Add registers a new scheduled scan and returns it.
func (s *Scheduler) Add(target, profile, cronExpr string) (*ScheduledScan, error) {
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	nextRun, err := parseCron(cronExpr, time.Now())
	if err != nil {
		return nil, fmt.Errorf("invalid cron expression: %w", err)
	}

	scan := &ScheduledScan{
		ID:       uuid.New().String(),
		Target:   target,
		Profile:  profile,
		CronExpr: cronExpr,
		NextRun:  nextRun,
		Enabled:  true,
	}

	s.mu.Lock()
	s.scans[scan.ID] = scan
	s.mu.Unlock()

	return scan, nil
}

// Remove deletes a scheduled scan by ID.
func (s *Scheduler) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.scans[id]; !ok {
		return fmt.Errorf("scheduled scan %s not found", id)
	}
	delete(s.scans, id)
	return nil
}

// ListAll returns a snapshot of all scheduled scans.
func (s *Scheduler) ListAll() []*ScheduledScan {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*ScheduledScan, 0, len(s.scans))
	for _, sc := range s.scans {
		cp := *sc
		out = append(out, &cp)
	}
	return out
}

// Start runs the scheduler loop in the background until ctx is cancelled.
// It wakes up once per minute to check for due scans.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.tick(now)
			}
		}
	}()
}

// tick fires any scheduled scans whose NextRun is in the past.
func (s *Scheduler) tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sc := range s.scans {
		if !sc.Enabled {
			continue
		}
		if now.Before(sc.NextRun) {
			continue
		}

		// Fire the scan asynchronously so we don't block the ticker.
		target := sc.Target
		profile := sc.Profile
		go s.trigger(target, profile)

		// Advance to the next scheduled time.
		t := now
		sc.LastRun = &t
		next, err := parseCron(sc.CronExpr, now)
		if err == nil {
			sc.NextRun = next
		}
	}
}
