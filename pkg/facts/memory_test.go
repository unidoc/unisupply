package facts

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

var day = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

func TestMemoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	var s Store = m

	if _, ok, err := s.GetModule(ctx, "example.com/a", "v1.0.0"); ok || err != nil {
		t.Fatalf("empty store: %v %v", ok, err)
	}
	mod := &Module{Path: "example.com/a", Version: "v1.0.0", FetchedAt: day, Source: "module_proxy",
		Info: scanner.MaintenanceInfo{Archived: true, LastRelease: day.AddDate(-3, 0, 0)}}
	if err := s.PutModule(ctx, mod); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetModule(ctx, "example.com/a", "v1.0.0")
	if err != nil || !ok || !got.Info.Archived || !got.FetchedAt.Equal(day) {
		t.Fatalf("GetModule = %+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.GetModule(ctx, "example.com/a", "v1.0.1"); ok {
		t.Error("a module is stored per version")
	}
	got.Info.Archived = false
	if again, _, _ := s.GetModule(ctx, "example.com/a", "v1.0.0"); !again.Info.Archived {
		t.Error("changing what Get returned must not change the store")
	}

	adv := &Advisory{ID: "GO-2026-0001", Aliases: []string{"CVE-2026-1"}, Severity: "HIGH", SeveritySource: "osv", KEVChecked: true, InKEV: true, FetchedAt: day}
	if err := s.PutAdvisory(ctx, adv); err != nil {
		t.Fatal(err)
	}
	adv.Aliases[0] = "changed"
	ga, ok, _ := s.GetAdvisory(ctx, "GO-2026-0001")
	if !ok || ga.Severity != "HIGH" || !ga.InKEV || ga.Aliases[0] != "CVE-2026-1" {
		t.Errorf("GetAdvisory = %+v %v", ga, ok)
	}

	fix := &Fix{Module: "example.com/a", Version: "v1.2.0", ReleasedAt: day.AddDate(0, 0, -5), Source: "module_proxy", RequiresGo: "1.24", FetchedAt: day}
	if err := s.PutFix(ctx, fix); err != nil {
		t.Fatal(err)
	}
	if gf, ok, _ := s.GetFix(ctx, "example.com/a", "v1.2.0"); !ok || gf.RequiresGo != "1.24" || !gf.ReleasedAt.Equal(fix.ReleasedAt) {
		t.Errorf("GetFix = %+v %v", gf, ok)
	}
	// a later Put replaces
	_ = s.PutFix(ctx, &Fix{Module: "example.com/a", Version: "v1.2.0", ReleasedAt: day, FetchedAt: day})
	if gf, _, _ := s.GetFix(ctx, "example.com/a", "v1.2.0"); !gf.ReleasedAt.Equal(day) {
		t.Errorf("Put must replace: %+v", gf)
	}
}

func TestMemoryConcurrent(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = m.PutAdvisory(ctx, &Advisory{ID: "GO-1", FetchedAt: day})
				_, _, _ = m.GetAdvisory(ctx, "GO-1")
				_ = m.PutModule(ctx, &Module{Path: "p", Version: "v", FetchedAt: day})
				_, _, _ = m.GetModule(ctx, "p", "v")
			}
		}()
	}
	wg.Wait()
}

func TestNoneAlwaysMisses(t *testing.T) {
	ctx := context.Background()
	if err := None.PutAdvisory(ctx, &Advisory{ID: "GO-1"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := None.GetAdvisory(ctx, "GO-1"); ok || err != nil {
		t.Errorf("None.GetAdvisory = %v %v", ok, err)
	}
}

func TestFresh(t *testing.T) {
	for name, c := range map[string]struct {
		fetched time.Time
		want    bool
	}{
		"just now":            {day, true},
		"within the age":      {day.Add(-23 * time.Hour), true},
		"too old":             {day.Add(-25 * time.Hour), false},
		"never fetched":       {time.Time{}, false},
		"from after the date": {day.Add(48 * time.Hour), true},
	} {
		if got := Fresh(c.fetched, day, DefaultPolicy.Module); got != c.want {
			t.Errorf("%s: Fresh = %v, want %v", name, got, c.want)
		}
	}
}

func TestMaintenanceInfoAgeAt(t *testing.T) {
	info := scanner.MaintenanceInfo{LastRelease: day.AddDate(0, -3, 0), LastActivity: day.AddDate(0, -1, 0), MonthsSinceRelease: 3}
	info.AgeAt(day.AddDate(0, 6, 0))
	if info.MonthsSinceRelease != 9 || info.MonthsSinceActivity != 7 {
		t.Errorf("AgeAt = %d, %d", info.MonthsSinceRelease, info.MonthsSinceActivity)
	}
}
