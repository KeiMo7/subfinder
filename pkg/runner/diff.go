package runner

import (
	"errors"
	"os"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/diff"
)

// maxDiffGapCycles bounds how many historical cycles are inspected to
// back-fill hosts hidden by consecutive source failures.
const maxDiffGapCycles = 12

// runDiff persists this cycle's normalized snapshot and produces the
// cycle-over-cycle delta report.
//
// The whole diff path is best-effort: every failure is logged as a warning
// and never propagated, so a diff-store problem cannot fail the enumeration
// itself or change its exit code. The standard single-run output has already
// been written by the time this runs.
func (r *Runner) runDiff(domain string, sourceMap map[string]map[string]struct{}, resolved map[string]diff.HostStatus) {
	opts := r.options
	store := diff.NewStore(opts.DiffDir)

	cycle := opts.DiffCycle
	if cycle == "" {
		cycle = diff.CycleID(time.Now())
	}

	// In active mode the on-screen output drops unresolved hosts, but the
	// snapshot must keep every observed host (with its resolution status) so
	// that an unresolved -> resolved transition is detectable next cycle.
	diffHosts := sourceMap
	if resolved != nil && opts.RemoveWildcard {
		diffHosts = r.diffHostsWithStatus(sourceMap, resolved)
	}

	// Per-source health comes from the same statistics the -stats flag
	// prints. A source that errored or was skipped provides no coverage this
	// cycle and therefore cannot support a disappearance verdict.
	health := diff.HealthFromStatistics(r.passiveAgent.SourceNames(), r.passiveAgent.GetStatistics())
	snapshot := diff.BuildSnapshot(domain, cycle, diffHosts, resolved, health, time.Now())

	if err := store.SaveSnapshot(snapshot); err != nil {
		gologger.Warning().Msgf("Diff snapshot write failed for %s (continuing without delta): %s\n", domain, err)
		return
	}

	previous, err := store.LoadPrevious(domain, cycle)
	switch {
	case err == nil:
		// Normal incremental path.
	case errors.Is(err, diff.ErrNoHistory):
		// First recorded cycle: emit a full inventory explicitly flagged as
		// such, never silently presented as an incremental delta.
		gologger.Info().Msgf("No previous diff snapshot for %s; this cycle is stored as a full inventory, no delta is produced\n", domain)
		r.persistAndSummarize(store, diff.Compare(nil, snapshot, nil, diff.CompareOptions{Now: time.Now()}), domain)
		return
	case errors.Is(err, os.ErrNotExist):
		gologger.Info().Msgf("Previous diff snapshot for %s is missing; this cycle is stored as a full inventory, no delta is produced\n", domain)
		r.persistAndSummarize(store, diff.Compare(nil, snapshot, nil, diff.CompareOptions{Now: time.Now()}), domain)
		return
	default:
		// A corrupted historical segment: name the exact cycle and impact,
		// then skip the delta rather than guessing from partial history.
		gologger.Warning().Msgf("Diff history for %s is unreadable (%s); current cycle was still persisted, skipping delta this run\n", domain, err)
		return
	}

	// Bounded window for gap recovery: enough cycles to cover the longest
	// tolerated consecutive-source-failure streak, never the whole history.
	history, err := store.LoadWindow(domain, cycle, maxDiffGapCycles)
	if err != nil {
		gologger.Warning().Msgf("Diff history window for %s is unreadable (%s); current cycle was still persisted, skipping delta this run\n", domain, err)
		return
	}

	report := diff.Compare(previous, snapshot, history, diff.CompareOptions{MaxGapCycles: maxDiffGapCycles, Now: time.Now()})
	r.persistAndSummarize(store, report, domain)
}

// persistAndSummarize writes the report into the store (plus the optional
// explicit output path) and logs a human-readable summary. Write failures are
// warned about but do not interrupt the main enumeration flow.
func (r *Runner) persistAndSummarize(store *diff.Store, report *diff.Report, domain string) {
	if err := store.SaveReport(report); err != nil {
		gologger.Warning().Msgf("Diff report write failed for %s (enumeration results are unaffected): %s\n", domain, err)
	} else {
		gologger.Info().Msgf("Diff report for %s cycle %s written to %s\n", domain, report.CurrentCycle, store.ReportPath(domain, report.CurrentCycle))
	}

	if r.options.DiffOutput != "" {
		if err := writeReportFile(r.options.DiffOutput, report); err != nil {
			gologger.Warning().Msgf("Optional diff output write failed for %s: %s\n", domain, err)
		}
	}

	summarizeDiff(report)
}
