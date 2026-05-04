package remediation_test

import (
	"testing"

	"github.com/bb-agent/mirage/internal/remediation"
)

func newItem(st *remediation.Store) *remediation.Item {
	return st.Create("finding-1", "SQL Injection in /search", "Details", "critical",
		"https://target.example.com", "SQLi", "flow-abc", 9.5)
}

func TestStore_Create(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	if it.ID == "" {
		t.Error("expected non-empty ID")
	}
	if it.Status != remediation.StatusOpen {
		t.Errorf("initial Status = %q, want open", it.Status)
	}
	if it.SLADeadline == nil {
		t.Error("SLADeadline should be set for critical severity")
	}
	if it.RiskScore != 9.5 {
		t.Errorf("RiskScore = %.1f, want 9.5", it.RiskScore)
	}
}

func TestStore_Get(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	got, ok := st.Get(it.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Title != "SQL Injection in /search" {
		t.Errorf("Title = %q, want SQL Injection in /search", got.Title)
	}

	_, ok = st.Get("ghost")
	if ok {
		t.Error("Get ghost: expected not found")
	}
}

func TestStore_List(t *testing.T) {
	st := remediation.NewStore()
	newItem(st)
	st.Create("f2", "XSS", "d", "high", "https://t.com", "XSS", "f2", 7.0)

	all := st.List("")
	if len(all) != 2 {
		t.Fatalf("List() = %d, want 2", len(all))
	}

	open := st.List("open")
	if len(open) != 2 {
		t.Fatalf("List(open) = %d, want 2", len(open))
	}
}

func TestStore_List_StatusFilter(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)
	st.UpdateStatus(it.ID, remediation.StatusFixed, "") //nolint

	open := st.List("open")
	if len(open) != 0 {
		t.Errorf("List(open) = %d, want 0 after fixing", len(open))
	}

	fixed := st.List("fixed")
	if len(fixed) != 1 {
		t.Errorf("List(fixed) = %d, want 1", len(fixed))
	}
}

func TestStore_UpdateStatus(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	transitions := []remediation.Status{
		remediation.StatusTriaged,
		remediation.StatusInProgress,
		remediation.StatusFixed,
		remediation.StatusVerified,
	}

	for _, status := range transitions {
		if err := st.UpdateStatus(it.ID, status, "security-team"); err != nil {
			t.Fatalf("UpdateStatus(%s): %v", status, err)
		}
		got, _ := st.Get(it.ID)
		if got.Status != status {
			t.Errorf("Status = %q, want %q", got.Status, status)
		}
	}

	// After setting to fixed, FixedAt should be set
	got, _ := st.Get(it.ID)
	if got.FixedAt == nil {
		t.Error("FixedAt should be set after status=fixed")
	}
}

func TestStore_UpdateStatus_NotFound(t *testing.T) {
	st := remediation.NewStore()
	if err := st.UpdateStatus("ghost", remediation.StatusFixed, ""); err == nil {
		t.Error("expected error for nonexistent item")
	}
}

func TestStore_AddNote(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	note, err := st.AddNote(it.ID, "alice", "Confirmed exploitable via manual testing.")
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if note.ID == "" {
		t.Error("note ID should be set")
	}
	if note.Content != "Confirmed exploitable via manual testing." {
		t.Errorf("Content = %q", note.Content)
	}

	got, _ := st.Get(it.ID)
	if len(got.Notes) != 1 {
		t.Errorf("Notes count = %d, want 1", len(got.Notes))
	}
}

func TestStore_AddNote_NotFound(t *testing.T) {
	st := remediation.NewStore()
	_, err := st.AddNote("ghost", "a", "content")
	if err == nil {
		t.Error("expected error adding note to nonexistent item")
	}
}

func TestStore_SetTicket_Jira(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	if err := st.SetTicket(it.ID, "SEC-42", "https://jira.example.com/browse/SEC-42", 0, ""); err != nil {
		t.Fatalf("SetTicket Jira: %v", err)
	}
	got, _ := st.Get(it.ID)
	if got.JiraKey != "SEC-42" {
		t.Errorf("JiraKey = %q, want SEC-42", got.JiraKey)
	}
}

func TestStore_SetTicket_GitHub(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	if err := st.SetTicket(it.ID, "", "", 123, "https://github.com/org/repo/issues/123"); err != nil {
		t.Fatalf("SetTicket GitHub: %v", err)
	}
	got, _ := st.Get(it.ID)
	if got.GithubIssue != 123 {
		t.Errorf("GithubIssue = %d, want 123", got.GithubIssue)
	}
}

func TestStore_SetTicket_NotFound(t *testing.T) {
	st := remediation.NewStore()
	if err := st.SetTicket("ghost", "KEY", "url", 0, ""); err == nil {
		t.Error("expected error for nonexistent item")
	}
}

func TestStore_Delete(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	if err := st.Delete(it.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := st.Get(it.ID); ok {
		t.Error("item still exists after Delete")
	}
	if err := st.Delete(it.ID); err == nil {
		t.Error("expected error deleting nonexistent item")
	}
}

func TestStore_ByFindingID(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st) // FindingID = "finding-1"

	got := st.ByFindingID("finding-1")
	if got == nil {
		t.Fatal("ByFindingID: not found")
	}
	if got.ID != it.ID {
		t.Errorf("ID = %q, want %q", got.ID, it.ID)
	}

	if st.ByFindingID("unknown") != nil {
		t.Error("ByFindingID unknown should return nil")
	}
}

func TestItem_SLAStatus(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st) // critical: 24h SLA

	status := it.SLAStatus()
	// Fresh item — SLA should not be breached yet
	if status == "breached" {
		t.Errorf("fresh critical item SLA = %q, should not be breached", status)
	}
	if status == "no_sla" {
		t.Error("critical item should have SLA set")
	}
}

func TestItem_IsTerminal(t *testing.T) {
	st := remediation.NewStore()
	it := newItem(st)

	if it.IsTerminal() {
		t.Error("open item should not be terminal")
	}

	st.UpdateStatus(it.ID, remediation.StatusVerified, "") //nolint
	got, _ := st.Get(it.ID)
	if !got.IsTerminal() {
		t.Error("verified item should be terminal")
	}
}
