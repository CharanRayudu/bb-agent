package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
	"github.com/google/uuid"
)

// Store persists decisions, approvals, and authorization snapshots.
type Store interface {
	AppendDecision(Decision) error
	Decisions() []Decision
	SaveApproval(policy.Approval) error
	ApprovalsForFlow(flowID string) []policy.Approval
	SaveAuthorization(policy.Authorization) error
}

// MemoryStore is the process-local audit log used in tests and as the
// read model in front of PostgreSQL.
type MemoryStore struct {
	mu             sync.Mutex
	decisions      []Decision
	approvals      []policy.Approval
	authorizations []policy.Authorization
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) AppendDecision(d Decision) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions = append(s.decisions, d)
	return nil
}

func (s *MemoryStore) Decisions() []Decision {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Decision, len(s.decisions))
	copy(out, s.decisions)
	return out
}

func (s *MemoryStore) SaveApproval(a policy.Approval) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.approvals {
		if s.approvals[i].ID == a.ID && a.ID != "" {
			s.approvals[i] = a
			return nil
		}
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	s.approvals = append(s.approvals, a)
	return nil
}

func (s *MemoryStore) ApprovalsForFlow(flowID string) []policy.Approval {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []policy.Approval
	for _, a := range s.approvals {
		if a.FlowID == flowID {
			out = append(out, a)
		}
	}
	return out
}

func (s *MemoryStore) SaveAuthorization(a policy.Authorization) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizations = append(s.authorizations, a)
	return nil
}

// SQLExec is the subset of *sql.DB used for audit inserts.
type SQLExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type sqlStore struct {
	mem *MemoryStore
	db  SQLExec
}

func NewDurableStore(mem *MemoryStore, db SQLExec) Store {
	if mem == nil {
		mem = NewMemoryStore()
	}
	if db == nil {
		return mem
	}
	return &sqlStore{mem: mem, db: db}
}

func (s *sqlStore) AppendDecision(d Decision) error {
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO action_decisions (id, action_id, flow_id, allowed, code, reason, idempotency_key, actor_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		d.ID, d.ActionID, d.FlowID, d.Allowed, d.Code, d.Reason, d.IdempotencyKey, d.ActorID, d.CreatedAt); err != nil {
		return err
	}
	return s.mem.AppendDecision(d)
}

func (s *sqlStore) Decisions() []Decision { return s.mem.Decisions() }

func (s *sqlStore) SaveApproval(a policy.Approval) error {
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO approval_requests (id, action_key, flow_id, phase, status, actor, reason, expires_at, created_at, method, target, digest, risk, capability)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, actor = EXCLUDED.actor, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
			method = EXCLUDED.method, target = EXCLUDED.target, digest = EXCLUDED.digest, risk = EXCLUDED.risk, capability = EXCLUDED.capability`,
		a.ID, a.ActionKey, a.FlowID, a.Phase, a.Status, a.Actor, a.Reason, nullableTime(a.ExpiresAt), a.CreatedAt,
		a.Method, a.Target, a.Digest, a.Risk, a.Capability); err != nil {
		return err
	}
	return s.mem.SaveApproval(a)
}

func (s *sqlStore) ApprovalsForFlow(flowID string) []policy.Approval {
	return s.mem.ApprovalsForFlow(flowID)
}

func (s *sqlStore) SaveAuthorization(a policy.Authorization) error {
	document, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO engagement_authorizations (id, engagement_id, flow_id, owner, autonomy, expires_at, created_at, document)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7::jsonb)
		ON CONFLICT (id) DO UPDATE SET autonomy = EXCLUDED.autonomy, expires_at = EXCLUDED.expires_at, document = EXCLUDED.document`,
		a.ID, a.EngagementID, a.FlowID, a.Owner, string(a.Autonomy), nullableTime(a.ExpiresAt), string(document)); err != nil {
		return err
	}
	return s.mem.SaveAuthorization(a)
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
