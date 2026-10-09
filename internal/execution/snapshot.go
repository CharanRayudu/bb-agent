package execution

import "github.com/bb-agent/mirage/internal/policy"

// Snapshot is the durable view restored after a process restart.
type Snapshot struct {
	Authorizations []policy.Authorization `json:"authorizations"`
	Approvals      []policy.Approval      `json:"approvals"`
}

// Export copies the engagement restrictions and approval state.
func (g *Gateway) Export() Snapshot {
	if g == nil {
		return Snapshot{}
	}
	snap := Snapshot{Authorizations: g.book.All()}
	switch store := g.store.(type) {
	case *MemoryStore:
		snap.Approvals = store.allLocked()
	case *sqlStore:
		if store.mem != nil {
			snap.Approvals = store.mem.allLocked()
		}
	}
	return snap
}

// Restore loads a previously exported snapshot into an empty gateway.
func Restore(gw *Gateway, snap Snapshot) {
	if gw == nil {
		return
	}
	for _, auth := range snap.Authorizations {
		gw.book.Put(auth)
	}
	for _, approval := range snap.Approvals {
		_ = gw.store.SaveApproval(approval)
	}
}
