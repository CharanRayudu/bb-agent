package schedplan_test

import (
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/schedplan"
)

func TestStore_CreateAndList(t *testing.T) {
	st := schedplan.NewStore()

	sc, err := st.Create("Nightly Scan", "https://target.example.com", "owasp-top10", "OWASP Top 10", "@daily")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sc.ID == "" {
		t.Error("expected non-empty ID")
	}
	if sc.Name != "Nightly Scan" {
		t.Errorf("Name = %q, want Nightly Scan", sc.Name)
	}
	if !sc.Enabled {
		t.Error("expected Enabled=true by default")
	}
	if sc.NextRun.IsZero() {
		t.Error("expected non-zero NextRun")
	}
	if sc.CronLabel != "Daily" {
		t.Errorf("CronLabel = %q, want Daily", sc.CronLabel)
	}

	list := st.List()
	if len(list) != 1 {
		t.Fatalf("List: got %d, want 1", len(list))
	}
}

func TestStore_Create_ValidationErrors(t *testing.T) {
	st := schedplan.NewStore()

	if _, err := st.Create("", "https://x.com", "", "", "@daily"); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := st.Create("s", "", "", "", "@daily"); err == nil {
		t.Error("expected error for empty target")
	}
	if _, err := st.Create("s", "https://x.com", "", "", ""); err == nil {
		t.Error("expected error for empty cron")
	}
	if _, err := st.Create("s", "https://x.com", "", "", "@invalid"); err == nil {
		t.Error("expected error for unknown cron preset")
	}
}

func TestStore_Create_AllPresets(t *testing.T) {
	st := schedplan.NewStore()
	for preset := range schedplan.CronPresets {
		_, err := st.Create("p", "https://x.com", "", "", preset)
		if err != nil {
			t.Errorf("Create with preset %q: %v", preset, err)
		}
	}
}

func TestStore_Get(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("s", "https://a.com", "", "", "@weekly")

	got, ok := st.Get(sc.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Target != "https://a.com" {
		t.Errorf("Target = %q, want https://a.com", got.Target)
	}

	_, ok = st.Get("nope")
	if ok {
		t.Error("Get nonexistent: expected not found")
	}
}

func TestStore_Update(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("orig", "https://old.com", "p1", "Profile 1", "@hourly")

	err := st.Update(sc.ID, "new", "https://new.com", "p2", "Profile 2", "@weekly")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := st.Get(sc.ID)
	if got.Name != "new" {
		t.Errorf("Name = %q, want new", got.Name)
	}
	if got.Target != "https://new.com" {
		t.Errorf("Target = %q, want https://new.com", got.Target)
	}
	if got.Cron != "@weekly" {
		t.Errorf("Cron = %q, want @weekly", got.Cron)
	}
}

func TestStore_Update_NotFound(t *testing.T) {
	st := schedplan.NewStore()
	if err := st.Update("ghost", "n", "t", "", "", "@daily"); err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestStore_Update_BadCron(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("s", "https://x.com", "", "", "@daily")
	if err := st.Update(sc.ID, "s", "https://x.com", "", "", "@bad"); err == nil {
		t.Error("expected error for invalid cron preset")
	}
}

func TestStore_Delete(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("s", "https://x.com", "", "", "@daily")

	if err := st.Delete(sc.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := st.Get(sc.ID); ok {
		t.Error("schedule still exists after Delete")
	}
	if err := st.Delete(sc.ID); err == nil {
		t.Error("expected error deleting nonexistent ID")
	}
}

func TestStore_Toggle(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("s", "https://x.com", "", "", "@daily")

	// Toggle off
	got, err := st.Toggle(sc.ID)
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if got.Enabled {
		t.Error("expected Enabled=false after first toggle")
	}

	// Toggle on
	got, err = st.Toggle(sc.ID)
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if !got.Enabled {
		t.Error("expected Enabled=true after second toggle")
	}
	// NextRun should be refreshed on enable
	if got.NextRun.Before(time.Now()) {
		t.Error("expected NextRun in the future after enabling")
	}
}

func TestStore_Toggle_NotFound(t *testing.T) {
	st := schedplan.NewStore()
	if _, err := st.Toggle("ghost"); err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestStore_Due(t *testing.T) {
	st := schedplan.NewStore()

	// Create a schedule with NextRun already in the past
	sc, _ := st.Create("past", "https://x.com", "", "", "@daily")
	// Manually move NextRun to the past by toggling off then on with a manipulated store
	// We'll just check that a fresh schedule is NOT due (NextRun is in the future)
	due := st.Due()
	for _, d := range due {
		if d.ID == sc.ID {
			t.Error("fresh schedule should not be due immediately")
		}
	}
}

func TestStore_MarkRunningAndComplete(t *testing.T) {
	st := schedplan.NewStore()
	sc, _ := st.Create("s", "https://x.com", "", "", "@daily")

	st.MarkRunning(sc.ID)
	got, _ := st.Get(sc.ID)
	if got.LastStatus != "running" {
		t.Errorf("LastStatus = %q after MarkRunning, want running", got.LastStatus)
	}

	st.MarkComplete(sc.ID, "ok")
	got, _ = st.Get(sc.ID)
	if got.LastStatus != "ok" {
		t.Errorf("LastStatus = %q after MarkComplete, want ok", got.LastStatus)
	}
	if got.RunCount != 1 {
		t.Errorf("RunCount = %d, want 1", got.RunCount)
	}
	if got.LastRun == nil {
		t.Error("LastRun should be set after MarkComplete")
	}
	if got.NextRun.Before(time.Now()) {
		t.Error("NextRun should be rescheduled after MarkComplete")
	}
}

func TestStore_ListSortedByCreatedAt(t *testing.T) {
	st := schedplan.NewStore()
	for _, tgt := range []string{"a", "b", "c"} {
		st.Create("s", "https://"+tgt+".com", "", "", "@daily") //nolint
	}
	list := st.List()
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.Before(list[i-1].CreatedAt) {
			t.Errorf("list not sorted by CreatedAt at index %d", i)
		}
	}
}

func TestCronPresets_Coverage(t *testing.T) {
	expected := []string{"@hourly", "@every6h", "@every12h", "@daily", "@weekly", "@monthly"}
	for _, p := range expected {
		if _, ok := schedplan.CronPresets[p]; !ok {
			t.Errorf("CronPresets missing %q", p)
		}
		if _, ok := schedplan.CronLabel[p]; !ok {
			t.Errorf("CronLabel missing %q", p)
		}
	}
}
