package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// AgentRole defines the level of access a user has within the agent system.
type AgentRole string

const (
	AgentRoleAdmin    AgentRole = "admin"
	AgentRoleOperator AgentRole = "operator"
	AgentRoleViewer   AgentRole = "viewer"
)

// AgentUser represents a user in the agent RBAC system.
type AgentUser struct {
	Username string    `json:"username"`
	Role     AgentRole `json:"role"`
	APIKey   string    `json:"-"` // never serialised
}

// RBAC manages users and API-key–based authentication.
type RBAC struct {
	users map[string]*AgentUser // keyed by APIKey
	mu    sync.RWMutex
}

// NewRBAC creates an empty RBAC store.
func NewRBAC() *RBAC {
	return &RBAC{
		users: make(map[string]*AgentUser),
	}
}

// AddUser creates a new user with the given role and returns a freshly generated API key.
func (r *RBAC) AddUser(username string, role AgentRole) (apiKey string, err error) {
	if username == "" {
		return "", fmt.Errorf("username is required")
	}

	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}
	apiKey = "mrg_" + hex.EncodeToString(b)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.users[apiKey] = &AgentUser{
		Username: username,
		Role:     role,
		APIKey:   apiKey,
	}
	return apiKey, nil
}

// Authenticate looks up a user by their API key.
func (r *RBAC) Authenticate(apiKey string) (*AgentUser, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.users[apiKey]
	return u, ok
}

// CanWrite returns true for admin and operator roles.
func (r *RBAC) CanWrite(user *AgentUser) bool {
	if user == nil {
		return false
	}
	return user.Role == AgentRoleAdmin || user.Role == AgentRoleOperator
}

// CanRead returns true for all roles.
func (r *RBAC) CanRead(user *AgentUser) bool {
	return user != nil
}

// CanAdmin returns true only for the admin role.
func (r *RBAC) CanAdmin(user *AgentUser) bool {
	return user != nil && user.Role == AgentRoleAdmin
}

// UserCount returns the current number of registered users.
func (r *RBAC) UserCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.users)
}
