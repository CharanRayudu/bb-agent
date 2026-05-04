package profiles_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/profiles"
)

func TestStore_BuiltinsLoaded(t *testing.T) {
	st := profiles.NewStore()
	list := st.List("")
	if len(list) == 0 {
		t.Fatal("expected built-in profiles, got none")
	}

	ids := make(map[string]bool)
	for _, p := range list {
		ids[p.ID] = true
		if !p.Builtin {
			t.Errorf("profile %q should have Builtin=true", p.ID)
		}
	}

	required := []string{"quick-recon", "owasp-top10", "api-security", "cloud-container", "devsecops-full", "full-pentest"}
	for _, id := range required {
		if !ids[id] {
			t.Errorf("missing built-in profile %q", id)
		}
	}
}

func TestStore_Get_Builtin(t *testing.T) {
	st := profiles.NewStore()
	p, ok := st.Get("quick-recon")
	if !ok {
		t.Fatal("quick-recon not found")
	}
	if p.Name == "" {
		t.Error("Name should not be empty")
	}
	if p.Color == "" {
		t.Error("Color should not be empty")
	}
	if len(p.Agents) == 0 {
		t.Error("expected at least one agent config")
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	st := profiles.NewStore()
	_, ok := st.Get("nonexistent-id")
	if ok {
		t.Error("expected not found for unknown ID")
	}
}

func TestStore_List_CategoryFilter(t *testing.T) {
	st := profiles.NewStore()
	webProfiles := st.List("web")
	if len(webProfiles) == 0 {
		t.Error("expected at least one web profile")
	}
	for _, p := range webProfiles {
		if p.Category != "web" {
			t.Errorf("filtered profile category = %q, want web", p.Category)
		}
	}
}

func TestStore_Create(t *testing.T) {
	st := profiles.NewStore()
	agents := []profiles.AgentConfig{{ID: "xss_scanner", Enabled: true}}
	p, err := st.Create("My Custom Profile", "Desc", "custom", "#ff0000", agents, []string{"custom", "pentest"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" {
		t.Error("expected non-empty ID")
	}
	if p.Builtin {
		t.Error("custom profile should not be Builtin")
	}
	if p.Name != "My Custom Profile" {
		t.Errorf("Name = %q, want My Custom Profile", p.Name)
	}
	if p.UseCount != 0 {
		t.Errorf("UseCount = %d, want 0", p.UseCount)
	}

	// Verify it's in the list
	got, ok := st.Get(p.ID)
	if !ok {
		t.Fatal("custom profile not found after create")
	}
	if len(got.Agents) != 1 {
		t.Errorf("Agents length = %d, want 1", len(got.Agents))
	}
}

func TestStore_Create_ValidationError(t *testing.T) {
	st := profiles.NewStore()
	_, err := st.Create("", "desc", "custom", "#fff", nil, nil)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestStore_Update_Custom(t *testing.T) {
	st := profiles.NewStore()
	p, _ := st.Create("orig", "d", "custom", "#111", nil, nil)

	newAgents := []profiles.AgentConfig{{ID: "sqli_scanner", Enabled: true}}
	err := st.Update(p.ID, "updated", "new desc", "#222", newAgents, []string{"sql"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := st.Get(p.ID)
	if got.Name != "updated" {
		t.Errorf("Name = %q, want updated", got.Name)
	}
	if got.Color != "#222" {
		t.Errorf("Color = %q, want #222", got.Color)
	}
}

func TestStore_Update_Builtin_Rejected(t *testing.T) {
	st := profiles.NewStore()
	err := st.Update("quick-recon", "hacked", "d", "#000", nil, nil)
	if err == nil {
		t.Error("expected error updating built-in profile")
	}
}

func TestStore_Update_NotFound(t *testing.T) {
	st := profiles.NewStore()
	err := st.Update("ghost-id", "n", "d", "#000", nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestStore_Delete_Custom(t *testing.T) {
	st := profiles.NewStore()
	p, _ := st.Create("del", "d", "custom", "#fff", nil, nil)

	if err := st.Delete(p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := st.Get(p.ID); ok {
		t.Error("profile still exists after Delete")
	}
}

func TestStore_Delete_Builtin_Rejected(t *testing.T) {
	st := profiles.NewStore()
	if err := st.Delete("owasp-top10"); err == nil {
		t.Error("expected error deleting built-in profile")
	}
}

func TestStore_Delete_NotFound(t *testing.T) {
	st := profiles.NewStore()
	if err := st.Delete("ghost"); err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestStore_Clone_Builtin(t *testing.T) {
	st := profiles.NewStore()
	clone, err := st.Clone("owasp-top10")
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if clone.Builtin {
		t.Error("clone of built-in should not be Builtin")
	}
	if clone.ID == "owasp-top10" {
		t.Error("clone should have a new ID")
	}
	if clone.Name == "" {
		t.Error("clone should have a name")
	}
	if clone.UseCount != 0 {
		t.Errorf("clone UseCount = %d, want 0", clone.UseCount)
	}
}

func TestStore_Clone_Custom(t *testing.T) {
	st := profiles.NewStore()
	p, _ := st.Create("orig", "d", "custom", "#fff", []profiles.AgentConfig{{ID: "x", Enabled: true}}, nil)
	clone, err := st.Clone(p.ID)
	if err != nil {
		t.Fatalf("Clone custom: %v", err)
	}
	if clone.ID == p.ID {
		t.Error("clone must have different ID")
	}
}

func TestStore_Clone_NotFound(t *testing.T) {
	st := profiles.NewStore()
	_, err := st.Clone("ghost")
	if err == nil {
		t.Error("expected error cloning nonexistent profile")
	}
}

func TestStore_IncrementUseCount(t *testing.T) {
	st := profiles.NewStore()
	p, _ := st.Create("p", "d", "custom", "#fff", nil, nil)
	if p.UseCount != 0 {
		t.Fatalf("initial UseCount = %d, want 0", p.UseCount)
	}
	st.IncrementUseCount(p.ID)
	st.IncrementUseCount(p.ID)
	got, _ := st.Get(p.ID)
	if got.UseCount != 2 {
		t.Errorf("UseCount = %d, want 2", got.UseCount)
	}
}
