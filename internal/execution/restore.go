package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

// LoadState reads authorization documents and approval rows written by the
// durable store. A query error is returned to the caller so startup can fail
// closed instead of continuing with an empty book.
func LoadState(ctx context.Context, db *sql.DB, book *policy.Book, mem *MemoryStore) error {
	if db == nil {
		return nil
	}
	if book == nil {
		return fmt.Errorf("authorization book is nil")
	}
	if mem == nil {
		mem = NewMemoryStore()
	}
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(document::text, '{}') FROM engagement_authorizations`)
	if err != nil {
		return fmt.Errorf("load authorizations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var document string
		if err := rows.Scan(&document); err != nil {
			return fmt.Errorf("scan authorization: %w", err)
		}
		if document == "" || document == "{}" {
			continue
		}
		var auth policy.Authorization
		if err := json.Unmarshal([]byte(document), &auth); err != nil {
			return fmt.Errorf("decode authorization: %w", err)
		}
		if auth.FlowID == "" && auth.ID == "" {
			continue
		}
		book.Put(auth)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read authorizations: %w", err)
	}

	approvals, err := db.QueryContext(ctx, `
		SELECT id, action_key, flow_id, phase, status, actor, reason, expires_at, created_at,
		       method, target, digest, risk, capability
		FROM approval_requests`)
	if err != nil {
		return fmt.Errorf("load approvals: %w", err)
	}
	defer approvals.Close()
	for approvals.Next() {
		var approval policy.Approval
		var expires sql.NullTime
		var created time.Time
		if err := approvals.Scan(
			&approval.ID, &approval.ActionKey, &approval.FlowID, &approval.Phase, &approval.Status,
			&approval.Actor, &approval.Reason, &expires, &created,
			&approval.Method, &approval.Target, &approval.Digest, &approval.Risk, &approval.Capability,
		); err != nil {
			return fmt.Errorf("scan approval: %w", err)
		}
		if expires.Valid {
			approval.ExpiresAt = expires.Time
		}
		approval.CreatedAt = created
		if err := mem.SaveApproval(approval); err != nil {
			return err
		}
	}
	if err := approvals.Err(); err != nil {
		return fmt.Errorf("read approvals: %w", err)
	}
	return nil
}
