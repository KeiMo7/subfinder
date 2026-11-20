package diff

import (
	"fmt"
	"slices"
	"time"
)

// defaultMaxGapCycles bounds how far back recovery analysis walks. It keeps
// reads proportional to the outage rather than to the total history size.
const defaultMaxGapCycles = 12

// CompareOptions tunes the cycle-over-cycle comparison.
type CompareOptions struct {
	// MaxGapCycles limits the history window inspected for gap recovery.
	// Zero selects the default.
	MaxGapCycles int
	// Now overrides report generation time (mainly used in tests).
	Now time.Time
}

// Compare classifies every host in current relative to previous. history is
// the ordered, oldest-first set of cycles strictly between the last healthy
// observation window and previous; it is used solely for gap recovery and
// may be nil. The function is pure: the same pair of snapshots always yields
// an identical report.
//
// A nil previous snapshot means this is the first run: the returned report is
// marked FullSnapshot and contains the complete current inventory under
// Persistent-less New is intentionally avoided — first-run hosts are reported
// in New with FullSnapshot=true so downstream consumers can distinguish a
// baseline from a real incremental run.
func Compare(previous, current *Snapshot, history []*Snapshot, opts CompareOptions) *Report {
	if opts.MaxGapCycles <= 0 {
		opts.MaxGapCycles = defaultMaxGapCycles
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	report := &Report{
		FormatVersion: SnapshotFormatVersion,
		Domain:        current.Domain,
		CurrentCycle:  current.Cycle,
		GeneratedAt:   now.UTC(),
		NewBySource:   map[string]int{},
		NewByDomain:   map[string]int{},
	}

	currentHosts := current.hostMap()
	failedNow := current.failedSourceSet()
	for name := range failedNow {
		report.FailedSources = append(report.FailedSources, name)
	}
	slices.Sort(report.FailedSources)
	report.Degraded = len(report.FailedSources) > 0

	if previous == nil {
		report.FullSnapshot = true
		for _, host := range current.Hosts {
			report.New = append(report.New, Change{
				Host:     host.Host,
				Category: ChangeNew,
				ToStatus: host.Resolved,
				Sources:  slices.Clone(host.Sources),
				Reason:   "first recorded cycle; full inventory, not an incremental delta",
			})
		}
		finalizeReport(report, current.Domain)
		return report
	}

	report.PreviousCycle = previous.Cycle
	previousHosts := previous.hostMap()
	failedBefore := previous.failedSourceSet()

	// Hosts observed this cycle: new vs persistent, plus status changes.
	for _, host := range current.Hosts {
		prev, existed := previousHosts[host.Host]
		if !existed {
			classifyAbsentReturningHost(report, host, previous, history, failedBefore, current.Cycle)
			continue
		}

		change := Change{
			Host:       host.Host,
			Category:   ChangePersistent,
			FromStatus: prev.Resolved,
			ToStatus:   host.Resolved,
			Sources:    slices.Clone(host.Sources),
		}
		report.Persistent = append(report.Persistent, change)

		if isStatusChange(prev.Resolved, host.Resolved) {
			report.Status = append(report.Status, StatusChange{
				Host:       host.Host,
				FromStatus: prev.Resolved,
				ToStatus:   host.Resolved,
			})
		}
	}

	// Hosts observed last cycle but not this one: disappeared vs uncertain.
	for _, prev := range previous.Hosts {
		if _, stillThere := currentHosts[prev.Host]; stillThere {
			continue
		}
		report.classifyMissingHost(prev, failedNow, current)
	}

	finalizeReport(report, current.Domain)
	return report
}

// classifyAbsentReturningHost handles a host observed now but absent from the
// immediately previous snapshot. If older history proves the host existed
// before and the gap is fully explained by source failures, it is a recovery
// (and the missed cycles are back-filled); otherwise it is a genuine new
// host.
func classifyAbsentReturningHost(report *Report, host HostRecord, previous *Snapshot, history []*Snapshot, failedBefore map[string]struct{}, currentCycle string) {
	// Walk the window newest -> oldest looking for the last cycle that
	// observed the host. The window excludes `previous`, which is handled
	// separately below.
	lastSeen := -1
	gapCycles := []string{}
	allGapsExplained := true

	for i := len(history) - 1; i >= 0; i-- {
		snap := history[i]
		// Defensive: a store window can include the current cycle when a
		// cycle is re-run; never treat it as a historical gap.
		if snap.Cycle == currentCycle || snap.Cycle == previous.Cycle {
			continue
		}
		if _, observed := snap.hostMap()[host.Host]; observed {
			lastSeen = i
			break
		}
		// The host was not observed in this intermediate cycle. The gap is
		// only explainable if every source that currently reports the host
		// had failed then.
		if !sourcesCoveredByFailures(host.Sources, snap.failedSourceSet()) {
			allGapsExplained = false
			break
		}
		gapCycles = append(gapCycles, snap.Cycle)
	}

	// The immediately previous cycle also missed the host and must be part of
	// the explained gap.
	if !sourcesCoveredByFailures(host.Sources, failedBefore) {
		allGapsExplained = false
	} else {
		gapCycles = append(gapCycles, previous.Cycle)
	}

	if lastSeen >= 0 && allGapsExplained {
		slices.Sort(gapCycles)
		report.Recovered = append(report.Recovered, Change{
			Host:         host.Host,
			Category:     ChangeRecovered,
			ToStatus:     host.Resolved,
			Sources:      slices.Clone(host.Sources),
			MissingSince: history[lastSeen].Cycle,
			GapCycles:    gapCycles,
			Reason:       fmt.Sprintf("host unobserved during %d cycle(s) whose covering sources had failed; back-filled on recovery", len(gapCycles)),
		})
		return
	}

	report.New = append(report.New, Change{
		Host:     host.Host,
		Category: ChangeNew,
		ToStatus: host.Resolved,
		Sources:  slices.Clone(host.Sources),
	})
}

// classifyMissingHost decides whether a host missing this cycle truly
// disappeared or simply was not covered. A host can only be called
// disappeared when every source that previously reported it ran successfully
// this cycle and still did not report it; a single failed covering source
// forces an uncertain verdict.
func (r *Report) classifyMissingHost(prev HostRecord, failedNow map[string]struct{}, current *Snapshot) {
	covering := prev.Sources
	if len(covering) == 0 {
		// Defensive: a persisted host always carries at least one source.
		r.Uncertain = append(r.Uncertain, Change{
			Host:       prev.Host,
			Category:   ChangeUncertain,
			FromStatus: prev.Resolved,
			Sources:    slices.Clone(covering),
			Reason:     "no recorded covering source; cannot assert disappearance",
		})
		return
	}

	failedCovering := []string{}
	for _, source := range covering {
		if _, failed := failedNow[source]; failed {
			failedCovering = append(failedCovering, source)
		}
	}
	slices.Sort(failedCovering)

	if len(failedCovering) > 0 {
		r.Uncertain = append(r.Uncertain, Change{
			Host:     prev.Host,
			Category: ChangeUncertain,
			Sources:  slices.Clone(covering),
			Reason:   fmt.Sprintf("covering source(s) failed this cycle: %v; treated as not scanned, not disappeared", failedCovering),
		})
		return
	}

	// Every previously covering source ran (healthy or empty) and none
	// reported the host: a real disappearance. Sources that were never part
	// of this run are excluded from the decision by construction.
	if !sourcesRanInCycle(covering, current) {
		r.Uncertain = append(r.Uncertain, Change{
			Host:     prev.Host,
			Category: ChangeUncertain,
			Sources:  slices.Clone(covering),
			Reason:   "a covering source was not part of this cycle's source set; coverage is incomplete",
		})
		return
	}

	r.Disappeared = append(r.Disappeared, Change{
		Host:       prev.Host,
		Category:   ChangeDisappeared,
		FromStatus: prev.Resolved,
		Sources:    slices.Clone(covering),
	})
}

// sourcesCoveredByFailures reports whether every source in sources is present
// in the failed set for a cycle.
func sourcesCoveredByFailures(sources []string, failed map[string]struct{}) bool {
	if len(sources) == 0 {
		return false
	}
	for _, source := range sources {
		if _, ok := failed[source]; !ok {
			return false
		}
	}
	return true
}

// sourcesRanInCycle reports whether every source appears in the cycle's
// source records (i.e. the run actually attempted it).
func sourcesRanInCycle(sources []string, snapshot *Snapshot) bool {
	known := make(map[string]struct{}, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		known[source.Name] = struct{}{}
	}
	for _, source := range sources {
		if _, ok := known[source]; !ok {
			return false
		}
	}
	return true
}

// isStatusChange only flags transitions between known states. StatusUnknown
// (passive mode) never participates so enabling or disabling -active does
// not manufacture noise.
func isStatusChange(from, to HostStatus) bool {
	if from == StatusUnknown || to == StatusUnknown || from == to {
		return false
	}
	return true
}

// finalizeReport makes every report deterministic: stable ordering, source and
// target-domain aggregates.
func finalizeReport(report *Report, targetDomain string) {
	less := func(a, b Change) int { return compareStrings(a.Host, b.Host) }
	slices.SortFunc(report.New, less)
	slices.SortFunc(report.Disappeared, less)
	slices.SortFunc(report.Persistent, less)
	slices.SortFunc(report.Recovered, less)
	slices.SortFunc(report.Uncertain, less)
	slices.SortFunc(report.Status, func(a, b StatusChange) int { return compareStrings(a.Host, b.Host) })

	// New-host contribution per source. A host reported by N sources
	// contributes one to each of its N sources.
	for _, change := range report.New {
		for _, source := range change.Sources {
			report.NewBySource[source]++
		}
		report.NewByDomain[targetDomain]++
	}
	if len(report.NewBySource) == 0 {
		report.NewBySource = nil
	}
	if len(report.NewByDomain) == 0 {
		report.NewByDomain = nil
	}
}

func compareStrings(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
