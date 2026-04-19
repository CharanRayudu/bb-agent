package agent

import (
	"testing"
)

func TestRBAC_AddAndAuthenticate(t *testing.T) {
	t.Parallel()
	r := NewRBAC()

	key, err := r.AddUser("alice", AgentRoleAdmin)
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if key == "" {
		t.Fatal("AddUser returned empty API key")
	}

	user, ok := r.Authenticate(key)
	if !ok {
		t.Fatal("Authenticate should succeed with valid key")
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q, want %q", user.Username, "alice")
	}
	if user.Role != AgentRoleAdmin {
		t.Errorf("Role = %q, want %q", user.Role, AgentRoleAdmin)
	}
}

func TestRBAC_BadKey(t *testing.T) {
	t.Parallel()
	r := NewRBAC()
	_, ok := r.Authenticate("bad-key-xyz")
	if ok {
		t.Error("Authenticate should fail with invalid key")
	}
}

func TestRBAC_Permissions(t *testing.T) {
	t.Parallel()
	r := NewRBAC()

	cases := []struct {
		role      AgentRole
		wantAdmin bool
		wantWrite bool
		wantRead  bool
	}{
		{AgentRoleAdmin, true, true, true},
		{AgentRoleOperator, false, true, true},
		{AgentRoleViewer, false, false, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.role), func(t *testing.T) {
			t.Parallel()
			key, _ := r.AddUser("u_"+string(tc.role), tc.role)
			u, _ := r.Authenticate(key)
			if r.CanAdmin(u) != tc.wantAdmin {
				t.Errorf("CanAdmin = %v, want %v", r.CanAdmin(u), tc.wantAdmin)
			}
			if r.CanWrite(u) != tc.wantWrite {
				t.Errorf("CanWrite = %v, want %v", r.CanWrite(u), tc.wantWrite)
			}
			if r.CanRead(u) != tc.wantRead {
				t.Errorf("CanRead = %v, want %v", r.CanRead(u), tc.wantRead)
			}
		})
	}
}

func TestRBAC_UniqueKeys(t *testing.T) {
	t.Parallel()
	r := NewRBAC()
	k1, _ := r.AddUser("user1", AgentRoleViewer)
	k2, _ := r.AddUser("user2", AgentRoleViewer)
	if k1 == k2 {
		t.Error("Two users should receive different API keys")
	}
}

func TestRBAC_EmptyUsername(t *testing.T) {
	t.Parallel()
	r := NewRBAC()
	_, err := r.AddUser("", AgentRoleViewer)
	if err == nil {
		t.Error("AddUser with empty username should return error")
	}
}
