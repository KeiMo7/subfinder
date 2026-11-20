package diff

import (
	"testing"
	"time"
)

func fixedTime() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) }

func hosts(m map[string][]string) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(m))
	for host, sources := range m {
		set := make(map[string]struct{}, len(sources))
		for _, s := range sources {
			set[s] = struct{}{}
		}
		out[host] = set
	}
	return out
}

func snap(domain, cycle string, hostSources map[string][]string, health []SourceHealth, resolved map[string]HostStatus) *Snapshot {
	return BuildSnapshot(domain, cycle, hosts(hostSources), resolved, health, fixedTime())
}

func healthy(names ...string) []SourceHealth {
	out := make([]SourceHealth, 0, len(names))
	for _, n := range names {
		out = append(out, SourceHealth{Name: n})
	}
	return out
}

func findChange(changes []Change, host string) *Change {
	for i := range changes {
		if changes[i].Host == host {
			return &changes[i]
		}
	}
	return nil
}

// TestCompareNormalIncrement covers the baseline three-way split.
func TestCompareNormalIncrement(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com": {"crtsh"},
		"b.example.com": {"crtsh", "hackertarget"},
	}, healthy("crtsh", "hackertarget"), nil)

	cur := snap("example.com", "2026-W47", map[string][]string{
		"b.example.com": {"crtsh", "hackertarget"},
		"c.example.com": {"hackertarget"},
	}, healthy("crtsh", "hackertarget"), nil)

	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})

	if report.FullSnapshot {
		t.Fatal("expected incremental report, got full snapshot")
	}
	if got := findChange(report.New, "c.example.com"); got == nil {
		t.Fatalf("c.example.com must be new, got %+v", report.New)
	}
	if got := findChange(report.Disappeared, "a.example.com"); got == nil {
		t.Fatalf("a.example.com must be disappeared, got %+v", report.Disappeared)
	}
	if got := findChange(report.Persistent, "b.example.com"); got == nil {
		t.Fatalf("b.example.com must be persistent, got %+v", report.Persistent)
	}
	if len(report.Uncertain) != 0 || len(report.Recovered) != 0 {
		t.Fatalf("healthy cycles must not produce uncertain/recovered entries: %+v %+v", report.Uncertain, report.Recovered)
	}
	if report.NewBySource["hackertarget"] != 1 {
		t.Fatalf("new-by-source aggregation wrong: %+v", report.NewBySource)
	}
	if report.NewByDomain["example.com"] != 1 {
		t.Fatalf("new-by-domain aggregation wrong: %+v", report.NewByDomain)
	}
}

// TestCompareSourceFailureNotDisappeared is the hard acceptance assertion:
// when a source fails for the whole cycle, hosts it alone covered must be
// uncertain, never disappeared.
func TestCompareSourceFailureNotDisappeared(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com":    {"crtsh"},
		"b.example.com":    {"hackertarget"},
		"gone.example.com": {"hackertarget"},
	}, healthy("crtsh", "hackertarget"), nil)

	cur := snap("example.com", "2026-W47", map[string][]string{
		"b.example.com": {"hackertarget"},
	}, []SourceHealth{
		{Name: "crtsh", Errors: 1}, // whole-source failure
		{Name: "hackertarget"},
	}, nil)

	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})

	if !report.Degraded {
		t.Fatal("report must be marked degraded when a source fails")
	}
	if len(report.FailedSources) != 1 || report.FailedSources[0] != "crtsh" {
		t.Fatalf("failed sources wrong: %+v", report.FailedSources)
	}
	if got := findChange(report.Disappeared, "a.example.com"); got != nil {
		t.Fatalf("host covered only by failed source must NOT be disappeared: %+v", got)
	}
	got := findChange(report.Uncertain, "a.example.com")
	if got == nil {
		t.Fatalf("a.example.com must be uncertain, got %+v", report.Uncertain)
	}
	if got.Reason == "" {
		t.Fatal("uncertain change must explain the reason")
	}
	// A host whose covering source stayed healthy and still vanished is a
	// real disappearance.
	if got := findChange(report.Disappeared, "gone.example.com"); got == nil {
		t.Fatal("gone.example.com must be disappeared because hackertarget ran cleanly and stopped reporting it")
	}
	// The healthy source's absence of a host must never leak into uncertain.
	if findChange(report.Uncertain, "gone.example.com") != nil {
		t.Fatal("host with fully healthy coverage must not be uncertain")
	}
}

// TestCompareRecoveryBackfill: two consecutive failed cycles followed by a
// recovery must classify the returning host as recovered (not new) and name
// every missed cycle for back-filling.
func TestCompareRecoveryBackfill(t *testing.T) {
	c1 := snap("example.com", "2026-W45", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	c2 := snap("example.com", "2026-W46", map[string][]string{},
		[]SourceHealth{{Name: "crtsh", Errors: 1}}, nil)
	c3 := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)

	report := Compare(c2, c3, []*Snapshot{c1}, CompareOptions{Now: fixedTime()})

	got := findChange(report.Recovered, "a.example.com")
	if got == nil {
		t.Fatalf("a.example.com must be recovered, got new=%+v uncertain=%+v", report.New, report.Uncertain)
	}
	if got.MissingSince != "2026-W45" {
		t.Fatalf("MissingSince wrong: %q", got.MissingSince)
	}
	if len(got.GapCycles) != 1 || got.GapCycles[0] != "2026-W46" {
		t.Fatalf("gap cycles wrong: %+v", got.GapCycles)
	}
	if findChange(report.New, "a.example.com") != nil {
		t.Fatal("recovered host must not also be classified new")
	}
}

// TestCompareRecoveryAfterSingleFailedCycle covers requirement 一.2: absent
// last cycle due to a source failure, back this cycle -> recovery.
func TestCompareRecoveryAfterSingleFailedCycle(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{},
		[]SourceHealth{{Name: "crtsh", Errors: 1}}, nil)
	cur := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	older := snap("example.com", "2026-W45", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)

	report := Compare(prev, cur, []*Snapshot{older}, CompareOptions{Now: fixedTime()})
	if findChange(report.Recovered, "a.example.com") == nil {
		t.Fatalf("expected recovery, got %+v", report)
	}
}

// TestCompareNewHostWhenHealthyGap: if the host was missing while all its
// sources ran fine, the later appearance is genuinely new.
func TestCompareNewHostWhenHealthyGap(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{
		"keep.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	cur := snap("example.com", "2026-W47", map[string][]string{
		"keep.example.com":  {"crtsh"},
		"fresh.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)

	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})
	if findChange(report.New, "fresh.example.com") == nil {
		t.Fatalf("fresh host must be new: %+v", report.New)
	}
}

// TestCompareResolutionStatusChange covers requirement 一.4.
func TestCompareResolutionStatusChange(t *testing.T) {
	resPrev := map[string]HostStatus{"a.example.com": StatusUnresolved}
	resCur := map[string]HostStatus{"a.example.com": StatusResolved}
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), resPrev)
	cur := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), resCur)

	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})
	if len(report.Status) != 1 {
		t.Fatalf("expected one status change, got %+v", report.Status)
	}
	change := report.Status[0]
	if change.FromStatus != StatusUnresolved || change.ToStatus != StatusResolved {
		t.Fatalf("status transition wrong: %+v", change)
	}
	if findChange(report.Persistent, "a.example.com") == nil {
		t.Fatal("host remains persistent alongside its status change")
	}
}

// TestCompareUnknownStatusIgnored: passive mode (unknown) must not fabricate
// status changes when active mode later starts reporting.
func TestCompareUnknownStatusIgnored(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)
	cur := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), map[string]HostStatus{"a.example.com": StatusResolved})

	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})
	if len(report.Status) != 0 {
		t.Fatalf("unknown->resolved must not be a status change: %+v", report.Status)
	}
}

// TestCompareFirstRunFullInventory covers anomaly 三.1.
func TestCompareFirstRunFullInventory(t *testing.T) {
	cur := snap("example.com", "2026-W47", map[string][]string{
		"a.example.com": {"crtsh"},
	}, healthy("crtsh"), nil)

	report := Compare(nil, cur, nil, CompareOptions{Now: fixedTime()})
	if !report.FullSnapshot {
		t.Fatal("first run must be flagged full snapshot")
	}
	if report.PreviousCycle != "" {
		t.Fatal("full inventory must not claim a previous cycle")
	}
	if len(report.New) != 1 || report.New[0].Reason == "" {
		t.Fatalf("full inventory hosts must be listed with an explanatory reason: %+v", report.New)
	}
}

// TestCompareDeterministic is the hard acceptance assertion: running the same
// pair of cycles twice yields byte-identical conclusions.
func TestCompareDeterministic(t *testing.T) {
	prev := snap("example.com", "2026-W46", map[string][]string{
		"a.example.com": {"crtsh"},
		"b.example.com": {"hackertarget"},
	}, healthy("crtsh", "hackertarget"), nil)
	cur := snap("example.com", "2026-W47", map[string][]string{
		"b.example.com": {"hackertarget"},
		"c.example.com": {"crtsh"},
	}, []SourceHealth{{Name: "crtsh"}, {Name: "hackertarget", Errors: 1}}, nil)

	first := mustMarshal(t, Compare(prev, cur, nil, CompareOptions{Now: fixedTime()}))
	second := mustMarshal(t, Compare(prev, cur, nil, CompareOptions{Now: fixedTime()}))
	if string(first) != string(second) {
		t.Fatalf("same input produced different reports:\n%s\nvs\n%s", first, second)
	}
}

// TestNormalizedIdentity covers hard constraint 三... 一.硬约束.1: case and
// trailing-dot variants are the same host, not an add/remove pair.
func TestNormalizedIdentity(t *testing.T) {
	prev := BuildSnapshot("Example.COM.", "2026-W46",
		hosts(map[string][]string{"WWW.Example.COM.": {"CRTSH"}}),
		nil, healthy("crtsh"), fixedTime())
	cur := BuildSnapshot("example.com", "2026-W47",
		hosts(map[string][]string{"www.example.com": {"crtsh"}}),
		nil, healthy("crtsh"), fixedTime())

	if prev.Domain != "example.com" {
		t.Fatalf("domain not normalized: %q", prev.Domain)
	}
	report := Compare(prev, cur, nil, CompareOptions{Now: fixedTime()})
	if len(report.New) != 0 || len(report.Disappeared) != 0 {
		t.Fatalf("case/trailing-dot differences must be the same identity: %+v", report)
	}
	if findChange(report.Persistent, "www.example.com") == nil {
		t.Fatalf("host must be persistent: %+v", report.Persistent)
	}
}
