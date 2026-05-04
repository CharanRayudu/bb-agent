package remediation

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status represents the lifecycle state of a remediation item.
type Status string

const (
	StatusOpen       Status = "open"
	StatusTriaged    Status = "triaged"
	StatusInProgress Status = "in_progress"
	StatusFixed      Status = "fixed"
	StatusVerified   Status = "verified"
	StatusAccepted   Status = "accepted" // risk accepted / won't fix
	StatusFalsePos   Status = "false_positive"
)

// SLA deadlines in hours per severity.
var defaultSLA = map[string]int{
	"critical": 24,
	"high":     168,  // 7 days
	"medium":   720,  // 30 days
	"low":      2160, // 90 days
	"info":     8760, // 1 year
}

// Note is a single timestamped comment on a remediation item.
type Note struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// Item is a rich, trackable remediation record for a finding.
type Item struct {
	ID          string  `json:"id"`
	FindingID   string  `json:"finding_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Target      string  `json:"target"`
	FindingType string  `json:"finding_type"`
	FlowID      string  `json:"flow_id"`
	RiskScore   float64 `json:"risk_score"`

	Status   Status `json:"status"`
	Assignee string `json:"assignee,omitempty"`

	SLADeadline *time.Time `json:"sla_deadline,omitempty"`
	SLABreached bool       `json:"sla_breached"`
	DueDate     *time.Time `json:"due_date,omitempty"`

	Notes []Note `json:"notes"`

	// External ticket refs
	JiraKey     string `json:"jira_key,omitempty"`
	JiraURL     string `json:"jira_url,omitempty"`
	GithubIssue int    `json:"github_issue,omitempty"`
	GithubURL   string `json:"github_url,omitempty"`

	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FixedAt    *time.Time `json:"fixed_at,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// SLAStatus returns a UI-friendly SLA label.
func (it *Item) SLAStatus() string {
	if it.SLADeadline == nil {
		return "no_sla"
	}
	remaining := time.Until(*it.SLADeadline)
	if remaining < 0 {
		return "breached"
	}
	if remaining < 24*time.Hour {
		return "due_soon"
	}
	return "ok"
}

// IsTerminal returns true when the item is in a closed state.
func (it *Item) IsTerminal() bool {
	return it.Status == StatusVerified || it.Status == StatusAccepted || it.Status == StatusFalsePos
}

// Store manages remediation items in memory.
type Store struct {
	mu    sync.RWMutex
	items map[string]*Item
}

// NewStore creates an empty store.
func NewStore() *Store {
	return &Store{items: make(map[string]*Item)}
}

// Create adds a new remediation item derived from a finding.
func (st *Store) Create(findingID, title, description, severity, target, findingType, flowID string, riskScore float64) *Item {
	now := time.Now()
	deadline := computeSLADeadline(severity, now)
	it := &Item{
		ID:          uuid.New().String(),
		FindingID:   findingID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Target:      target,
		FindingType: findingType,
		FlowID:      flowID,
		RiskScore:   riskScore,
		Status:      StatusOpen,
		SLADeadline: deadline,
		Notes:       []Note{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	st.mu.Lock()
	st.items[it.ID] = it
	st.mu.Unlock()
	return it
}

// Get retrieves an item by ID.
func (st *Store) Get(id string) (*Item, bool) {
	st.mu.RLock()
	it, ok := st.items[id]
	st.mu.RUnlock()
	if !ok {
		return nil, false
	}
	cp := *it
	cp.Notes = append([]Note(nil), it.Notes...)
	cp.SLABreached = it.SLADeadline != nil && time.Now().After(*it.SLADeadline) && !it.IsTerminal()
	return &cp, true
}

// List returns all items, optionally filtered by status.
func (st *Store) List(statusFilter string) []*Item {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*Item, 0, len(st.items))
	for _, it := range st.items {
		if statusFilter != "" && string(it.Status) != statusFilter {
			continue
		}
		cp := *it
		cp.Notes = append([]Note(nil), it.Notes...)
		cp.SLABreached = it.SLADeadline != nil && time.Now().After(*it.SLADeadline) && !it.IsTerminal()
		out = append(out, &cp)
	}
	return out
}

// UpdateStatus transitions an item to a new status.
func (st *Store) UpdateStatus(id string, status Status, assignee string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	it, ok := st.items[id]
	if !ok {
		return fmt.Errorf("item %s not found", id)
	}
	now := time.Now()
	it.Status = status
	it.UpdatedAt = now
	if assignee != "" {
		it.Assignee = assignee
	}
	if status == StatusFixed && it.FixedAt == nil {
		it.FixedAt = &now
	}
	if status == StatusVerified && it.VerifiedAt == nil {
		it.VerifiedAt = &now
	}
	return nil
}

// AddNote appends a note to an item.
func (st *Store) AddNote(id, author, content string) (*Note, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	it, ok := st.items[id]
	if !ok {
		return nil, fmt.Errorf("item %s not found", id)
	}
	n := Note{
		ID:        uuid.New().String(),
		Author:    author,
		Content:   content,
		CreatedAt: time.Now(),
	}
	it.Notes = append(it.Notes, n)
	it.UpdatedAt = time.Now()
	return &n, nil
}

// SetTicket records an external ticket reference.
func (st *Store) SetTicket(id, jiraKey, jiraURL string, githubIssue int, githubURL string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	it, ok := st.items[id]
	if !ok {
		return fmt.Errorf("item %s not found", id)
	}
	if jiraKey != "" {
		it.JiraKey = jiraKey
		it.JiraURL = jiraURL
	}
	if githubIssue > 0 {
		it.GithubIssue = githubIssue
		it.GithubURL = githubURL
	}
	it.UpdatedAt = time.Now()
	return nil
}

// Delete removes an item.
func (st *Store) Delete(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.items[id]; !ok {
		return fmt.Errorf("item %s not found", id)
	}
	delete(st.items, id)
	return nil
}

// ByFindingID returns the item for a given finding ID (nil if none).
func (st *Store) ByFindingID(findingID string) *Item {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for _, it := range st.items {
		if it.FindingID == findingID {
			cp := *it
			return &cp
		}
	}
	return nil
}

func computeSLADeadline(severity string, from time.Time) *time.Time {
	hours, ok := defaultSLA[severity]
	if !ok {
		return nil
	}
	d := from.Add(time.Duration(hours) * time.Hour)
	return &d
}
