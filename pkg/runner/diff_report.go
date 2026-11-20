package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/diff"
)

// writeReportFile renders a delta report to an explicit user-supplied path
// using the same atomic-write guarantees as the store.
func writeReportFile(path string, report *diff.Report) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o644)
}

// summarizeDiff prints a compact, stable summary of the delta so Monday's run
// is actionable without opening the JSON report.
func summarizeDiff(report *diff.Report) {
	if report.FullSnapshot {
		gologger.Info().Msgf("Diff[%s] baseline full inventory: %d hosts (no previous cycle, no delta)\n",
			report.Domain, len(report.New))
		return
	}

	gologger.Info().Msgf("Diff[%s] %s -> %s: new=%d disappeared=%d persistent=%d recovered=%d uncertain=%d status_changed=%d degraded=%t\n",
		report.Domain, report.PreviousCycle, report.CurrentCycle,
		len(report.New), len(report.Disappeared), len(report.Persistent),
		len(report.Recovered), len(report.Uncertain), len(report.Status), report.Degraded)

	if len(report.FailedSources) > 0 {
		gologger.Warning().Msgf("Diff[%s] sources unavailable this cycle: %v — hosts covered only by them are marked uncertain, not disappeared\n",
			report.Domain, report.FailedSources)
	}

	if top := topNewSources(report, 5); len(top) > 0 {
		gologger.Info().Msgf("Diff[%s] top new-host sources: %v\n", report.Domain, top)
	}
}

// topNewSources returns up to limit "source=count" pairs sorted by descending
// count then name, answering which source contributed the most new hosts.
func topNewSources(report *diff.Report, limit int) []string {
	type pair struct {
		source string
		count  int
	}
	pairs := make([]pair, 0, len(report.NewBySource))
	for source, count := range report.NewBySource {
		pairs = append(pairs, pair{source, count})
	}
	slices.SortFunc(pairs, func(a, b pair) int {
		if a.count != b.count {
			return b.count - a.count
		}
		if a.source < b.source {
			return -1
		}
		if a.source > b.source {
			return 1
		}
		return 0
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.source+"="+strconv.Itoa(p.count))
	}
	return out
}

// diffHostsWithStatus returns the host->sources map for the diff snapshot,
// guaranteeing every host carrying a resolution status is present even when
// the active resolver filtered it out of the on-screen output.
func (r *Runner) diffHostsWithStatus(sourceMap map[string]map[string]struct{}, resolved map[string]diff.HostStatus) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(sourceMap)+len(resolved))
	for host, sources := range sourceMap {
		out[host] = sources
	}
	for host := range resolved {
		if _, ok := out[host]; !ok {
			out[host] = map[string]struct{}{}
		}
	}
	return out
}
