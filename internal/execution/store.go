package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// budgetStore increments an engagement budget inside PostgreSQL.
type budgetStore interface {
	TryConsumeBudget(ctx context.Context, engagementID string, max int) (used int, allowed bool, err error)
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

func (s *sqlStore) TryConsumeBudget(ctx context.Context, engagementID string, max int) (int, bool, error) {
	queryer, ok := s.db.(interface {
		QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	})
	if !ok || engagementID == "" {
		return 0, false, fmt.Errorf("engagement budget is not stored")
	}
	var used int
	var rows int
	err := queryer.QueryRowContext(ctx, engagementBudgetSQL, engagementID).Scan(&used, &rows)
	if err != nil {
		return 0, false, err
	}
	if rows == 0 {
		return 0, false, fmt.Errorf("engagement budget is not stored")
	}
	if used < 0 {
		if max > 0 {
			return max, false, nil
		}
		return 0, false, nil
	}
	return used, true, nil
}

const engagementBudgetSQL = `
WITH locked AS (
    SELECT COALESCE((document->>'requests_used')::int, 0) AS used,
           COALESCE((document->>'max_requests')::int, 0) AS max_requests
    FROM engagement_authorizations
    WHERE engagement_id = $1
    FOR UPDATE
),
stats AS (
    SELECT COALESCE(MAX(used), 0) AS used,
           COALESCE(MAX(max_requests), 0) AS max_requests,
           COUNT(*) AS n
    FROM locked
),
updated AS (
    UPDATE engagement_authorizations AS e
    SET document = jsonb_set(
        CASE WHEN e.document IS NULL OR e.document = 'null'::jsonb THEN '{}'::jsonb ELSE e.document END,
        '{requests_used}',
        to_jsonb((SELECT used FROM stats) + 1),
        true
    )
    WHERE e.engagement_id = $1
      AND (SELECT n FROM stats) > 0
      AND (
        (SELECT max_requests FROM stats) = 0
        OR (SELECT used FROM stats) < (SELECT max_requests FROM stats)
      )
    RETURNING COALESCE((document->>'requests_used')::int, 0) AS used
)
SELECT COALESCE((SELECT used FROM updated LIMIT 1), -1),
       COALESCE((SELECT n FROM stats), 0)`

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
