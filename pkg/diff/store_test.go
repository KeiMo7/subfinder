package diff

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func testStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir())
}

// TestStoreAtomicWriteAndReload: a saved snapshot reloads byte-consistently
// and leaves no temp files behind.
func TestStoreAtomicWriteAndReload(t *testing.T) {
	store := testStore(t)
	snapshot := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
		"b.example.com": {"crtsh", "hackertarget"},
	}, healthy("crtsh", "hackertarget"), nil)

	if err := store.SaveSnapshot(snapshot); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := store.LoadSnapshot("example.com", "2026-W47")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(mustMarshal(t, loaded)) != string(mustMarshal(t, snapshot)) {
		t.Fatalf("round trip changed the snapshot\n%+v\n%+v", loaded, snapshot)
	}

	// No leftover temp files anywhere in the tree.
	filepath.WalkDir(store.Root(), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && len(filepath.Base(path)) > 0 && filepath.Base(path)[0] == '.' {
			t.Fatalf("temporary file left behind: %s", path)
		}
		return nil
	})
}

// TestStoreNoTempOnKill: writing into a read-only directory fails cleanly and
// never produces a partial target file (simulates a killed mid-write leaving
// the previous good file intact).
func TestStoreNoPartialWrite(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)
	good := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	if err := store.SaveSnapshot(good); err != nil {
		t.Fatalf("save good snapshot: %v", err)
	}

	// Remove write permission from the snapshots directory; the atomic write
	// must fail without truncating the existing file.
	snapDir := filepath.Join(root, "example.com", "snapshots")
	if err := os.Chmod(snapDir, 0o555); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(snapDir, 0o755) })

	bad := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
		"b.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	err := store.SaveSnapshot(bad)
	if err == nil {
		t.Fatal("expected write failure in read-only directory")
	}

	loaded, err := store.LoadSnapshot("example.com", "2026-W47")
	if err != nil {
		t.Fatalf("previous good snapshot must survive failed write: %v", err)
	}
	if len(loaded.Hosts) != 1 {
		t.Fatalf("failed write corrupted the previous snapshot: %+v", loaded.Hosts)
	}
}

// TestStoreMissingHistory: first run has no previous cycle.
func TestStoreMissingHistory(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadPrevious("example.com", "2026-W47"); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("expected ErrNoHistory, got %v", err)
	}
	if cycles, err := store.ListCycles("example.com"); err != nil || len(cycles) != 0 {
		t.Fatalf("empty history expected, got %v %v", cycles, err)
	}
}

// TestStoreWindowBounded: LoadWindow returns only the requested tail and
// excludes the current cycle.
func TestStoreWindowBounded(t *testing.T) {
	store := testStore(t)
	cycles := []string{"2026-W44", "2026-W45", "2026-W46", "2026-W47"}
	for _, cycle := range cycles {
		s := snap("example.com", cycle, map[string][]string{
			"a.example.com": {"crtsh"},
		}, healthy("crtsh"), nil)
		if err := store.SaveSnapshot(s); err != nil {
			t.Fatalf("save %s: %v", cycle, err)
		}
	}
	got, err := store.LoadWindow("example.com", "2026-W47", 2)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(got) != 2 || got[0].Cycle != "2026-W45" || got[1].Cycle != "2026-W46" {
		t.Fatalf("window contents wrong: %+v", got)
	}

	all, err := store.ListCycles("example.com")
	if err != nil || !sort.StringsAreSorted(all) || len(all) != 4 {
		t.Fatalf("cycle listing wrong: %v %v", all, err)
	}
}

// TestStoreCorruptionLocated: a single corrupted cycle is pinpointed while
// neighboring cycles remain readable — the impact scope stays local.
func TestStoreCorruptionLocated(t *testing.T) {
	store := testStore(t)
	for _, cycle := range []string{"2026-W45", "2026-W46"} {
		if err := store.SaveSnapshot(snap("example.com", cycle,
			map[string][]string{"a.example.com": {"crtsh"}}, healthy("crtsh"), nil)); err != nil {
			t.Fatalf("save %s: %v", cycle, err)
		}
	}
	badPath := store.snapshotPath("example.com", "2026-W46")
	if err := os.WriteFile(badPath, []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	// The older cycle is still fine.
	if _, err := store.LoadSnapshot("example.com", "2026-W45"); err != nil {
		t.Fatalf("healthy neighbor must remain readable: %v", err)
	}

	_, err := store.LoadSnapshot("example.com", "2026-W46")
	var corruption *CorruptionError
	if !errors.As(err, &corruption) {
		t.Fatalf("expected CorruptionError, got %v", err)
	}
	if corruption.Cycle != "2026-W46" || corruption.Path != badPath {
		t.Fatalf("corruption scope wrong: %+v", corruption)
	}

	// Window reads surface the same precise error instead of silently
	// dropping the cycle.
	if _, err := store.LoadWindow("example.com", "2026-W47", 5); !errors.As(err, &corruption) {
		t.Fatalf("window must propagate corruption, got %v", err)
	}
}

// TestStoreReportAndTrend: reports persist and the trend window accumulates
// bounded counts across cycles.
func TestStoreReportAndTrend(t *testing.T) {
	store := testStore(t)
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	for _, cycle := range []string{"2026-W47", "2026-W48"} {
		cur := snap("example.com", cycle, map[string][]string{
			"a.example.com":                {"crtsh"},
			"new" + cycle + ".example.com": {"hackertarget"},
		}, healthy("crtsh", "hackertarget"), nil)
		report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})
		if err := store.SaveReport(report); err != nil {
			t.Fatalf("save report %s: %v", cycle, err)
		}
		prev = cur
	}

	trend, err := store.Trend("example.com", 10)
	if err != nil {
		t.Fatalf("trend: %v", err)
	}
	if len(trend) != 2 {
		t.Fatalf("expected two trend points, got %+v", trend)
	}
	for _, point := range trend {
		if point.New != 1 {
			t.Fatalf("each cycle adds one new host: %+v", point)
		}
	}

	// Window limiting works on trends too.
	bounded, err := store.Trend("example.com", 1)
	if err != nil || len(bounded) != 1 || bounded[0].Cycle != "2026-W48" {
		t.Fatalf("bounded trend wrong: %+v %v", bounded, err)
	}
}

func TestCycleID(t *testing.T) {
	// 2026-11-21 is a Saturday in ISO week 47.
	got := CycleID(fixedTime())
	if got != "2026-W47" {
		t.Fatalf("cycle id wrong: %s", got)
	}
}

func TestClassifySourceHealth(t *testing.T) {
	cases := []struct {
		health SourceHealth
		want   SourceState
	}{
		{SourceHealth{Name: "a"}, SourceHealthy},
		{SourceHealth{Name: "b", Errors: 2}, SourceFailed},
		{SourceHealth{Name: "c", Skipped: true}, SourceFailed},
	}
	for _, tc := range cases {
		// contributed count is passed by the builder from observed hosts.
		got := classifySource(tc.health, 1)
		if got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.health.Name, got, tc.want)
		}
	}
	if got := classifySource(SourceHealth{Name: "empty"}, 0); got != SourceEmpty {
		t.Fatalf("error-free zero-result source must be empty, got %s", got)
	}
}
