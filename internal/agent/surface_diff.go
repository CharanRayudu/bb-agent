package agent

import (
	"sync"

	"github.com/google/uuid"
)

// EndpointRecord describes a single HTTP endpoint discovered during a scan.
type EndpointRecord struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Params []string `json:"params,omitempty"`
}

// SurfaceDiff holds the delta between two endpoint sets.
type SurfaceDiff struct {
	Added   []EndpointRecord `json:"added"`
	Removed []EndpointRecord `json:"removed"`
	Changed []EndpointRecord `json:"changed"`
}

// DiffSurfaces compares two endpoint lists and returns the delta.
func DiffSurfaces(previous, current []EndpointRecord) SurfaceDiff {
	key := func(e EndpointRecord) string { return e.Method + ":" + e.URL }

	prevMap := make(map[string]EndpointRecord, len(previous))
	for _, e := range previous {
		prevMap[key(e)] = e
	}

	currMap := make(map[string]EndpointRecord, len(current))
	for _, e := range current {
		currMap[key(e)] = e
	}

	var diff SurfaceDiff

	// Added or changed
	for k, e := range currMap {
		if prev, ok := prevMap[k]; !ok {
			diff.Added = append(diff.Added, e)
		} else {
			// Check if params changed
			if !paramSetsEqual(prev.Params, e.Params) {
				diff.Changed = append(diff.Changed, e)
			}
		}
	}

	// Removed
	for k, e := range prevMap {
		if _, ok := currMap[k]; !ok {
			diff.Removed = append(diff.Removed, e)
		}
	}

	return diff
}

func paramSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

// SurfaceStore stores endpoint records per flow, thread-safely.
type SurfaceStore struct {
	mu      sync.RWMutex
	surfaces map[uuid.UUID][]EndpointRecord
}

// NewSurfaceStore creates an empty surface store.
func NewSurfaceStore() *SurfaceStore {
	return &SurfaceStore{surfaces: make(map[uuid.UUID][]EndpointRecord)}
}

// Set replaces the endpoint list for a flow.
func (s *SurfaceStore) Set(flowID uuid.UUID, endpoints []EndpointRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.surfaces[flowID] = endpoints
}

// Get retrieves the endpoint list for a flow.
func (s *SurfaceStore) Get(flowID uuid.UUID) []EndpointRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.surfaces[flowID]
}
