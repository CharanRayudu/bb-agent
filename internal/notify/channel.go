package notify

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

type ChannelType string

const (
	ChannelSlack   ChannelType = "slack"
	ChannelWebhook ChannelType = "webhook"
	ChannelEmail   ChannelType = "email"
)

// SupportedEvents are the event names channels can subscribe to.
var SupportedEvents = []string{
	"critical_finding",
	"high_finding",
	"scan_complete",
	"sla_breach",
	"schedule_fired",
	"monitor_alert",
}

// ChannelConfig holds type-specific connection details.
type ChannelConfig struct {
	// Slack & generic webhook
	WebhookURL string `json:"webhook_url,omitempty"`
	// Slack channel name (optional, overrides default)
	SlackChannel string `json:"slack_channel,omitempty"`
	// Generic HTTP: extra request headers
	Headers map[string]string `json:"headers,omitempty"`
	// Email
	SMTPHost string   `json:"smtp_host,omitempty"`
	SMTPPort int      `json:"smtp_port,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
}

// Channel is a configured notification destination.
type Channel struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Type      ChannelType   `json:"type"`
	Enabled   bool          `json:"enabled"`
	Config    ChannelConfig `json:"config"`
	Events    []string      `json:"events"`
	TestedAt  *time.Time    `json:"tested_at,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return "ch_" + hex.EncodeToString(b)
}

// Store is a thread-safe in-memory channel repository.
type Store struct {
	mu    sync.RWMutex
	items map[string]*Channel
}

func NewStore() *Store {
	return &Store{items: make(map[string]*Channel)}
}

func (s *Store) List() []*Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Channel, 0, len(s.items))
	for _, ch := range s.items {
		cp := *ch
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *Store) Get(id string) (*Channel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.items[id]
	if !ok {
		return nil, false
	}
	cp := *ch
	return &cp, true
}

// ForEvent returns all enabled channels subscribed to the given event.
func (s *Store) ForEvent(event string) []*Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Channel
	for _, ch := range s.items {
		if !ch.Enabled {
			continue
		}
		for _, e := range ch.Events {
			if e == event {
				cp := *ch
				out = append(out, &cp)
				break
			}
		}
	}
	return out
}

func (s *Store) Create(name string, chType ChannelType, cfg ChannelConfig, events []string) (*Channel, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	switch chType {
	case ChannelSlack, ChannelWebhook, ChannelEmail:
	default:
		return nil, errors.New("type must be slack, webhook, or email")
	}
	now := time.Now()
	ch := &Channel{
		ID:        newID(),
		Name:      name,
		Type:      chType,
		Enabled:   true,
		Config:    cfg,
		Events:    events,
		CreatedAt: now,
	}
	s.mu.Lock()
	s.items[ch.ID] = ch
	s.mu.Unlock()
	cp := *ch
	return &cp, nil
}

func (s *Store) Update(id, name string, cfg ChannelConfig, events []string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.items[id]
	if !ok {
		return errors.New("channel not found")
	}
	ch.Name = name
	ch.Config = cfg
	ch.Events = events
	ch.Enabled = enabled
	return nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return errors.New("channel not found")
	}
	delete(s.items, id)
	return nil
}

func (s *Store) MarkTested(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.items[id]; ok {
		now := time.Now()
		ch.TestedAt = &now
	}
}
