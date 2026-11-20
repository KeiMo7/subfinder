package diff

import (
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SourceHealth is the raw per-source outcome collected while an enumeration
// runs. The runner fills one of these for every selected source.
type SourceHealth struct {
	Name    string
	Errors  int
	Results int
	// Skipped mirrors subscraping.Statistics.Skipped: the source did not run
	// (e.g. missing API key) and therefore provided no coverage.
	Skipped bool
}

// BuildSnapshot normalizes raw enumeration output into a persisted Snapshot.
//
// hostSources maps each observed host to the sources that reported it. Hosts
// and source names are normalized here so that case or trailing-dot
// differences can never produce a spurious add/remove pair.
//
// resolved maps a host to its resolution status. A nil map (passive mode
// without -active) records StatusUnknown for every host.
//
// health holds one entry per source selected for the run. Sources absent
// from the map are treated as failed (they never reported completion).
func BuildSnapshot(domain, cycle string, hostSources map[string]map[string]struct{}, resolved map[string]HostStatus, health []SourceHealth, generatedAt time.Time) *Snapshot {
	domain = normalizeHost(domain)

	hostIndex := make(map[string]*HostRecord, len(hostSources))
	hosts := make([]HostRecord, 0, len(hostSources))
	for rawHost, rawSources := range hostSources {
		host := normalizeHost(rawHost)
		if host == "" {
			continue
		}
		sources := make([]string, 0, len(rawSources))
		seen := make(map[string]struct{}, len(rawSources))
		for source := range rawSources {
			source = normalizeHost(source)
			if source == "" {
				continue
			}
			if _, dup := seen[source]; dup {
				continue
			}
			seen[source] = struct{}{}
			sources = append(sources, source)
		}
		slices.Sort(sources)

		status := StatusUnknown
		if resolved != nil {
			if s, ok := resolved[host]; ok {
				status = s
			}
		}
		hosts = append(hosts, HostRecord{Host: host, Sources: sources, Resolved: status})
		hostIndex[host] = &hosts[len(hosts)-1]
	}
	slices.SortFunc(hosts, func(a, b HostRecord) int { return strings.Compare(a.Host, b.Host) })

	sourceRecords := make([]SourceRecord, 0, len(health))
	for _, h := range health {
		name := normalizeHost(h.Name)
		if name == "" {
			continue
		}
		// Recompute the contributed count from the normalized host index so
		// the record stays consistent even if raw per-source counters drift.
		contributed := 0
		for _, host := range hosts {
			if slices.Contains(host.Sources, name) {
				contributed++
			}
		}
		sourceRecords = append(sourceRecords, SourceRecord{
			Name:    name,
			State:   classifySource(h, contributed),
			Errors:  h.Errors,
			Results: contributed,
		})
	}
	slices.SortFunc(sourceRecords, func(a, b SourceRecord) int { return strings.Compare(a.Name, b.Name) })

	return &Snapshot{
		FormatVersion: SnapshotFormatVersion,
		Domain:        domain,
		Cycle:         cycle,
		GeneratedAt:   generatedAt.UTC(),
		Sources:       sourceRecords,
		Hosts:         hosts,
	}
}

// classifySource maps raw source statistics onto the three-state health model.
// Any error or skip means the source cannot be trusted for disappearance
// decisions this cycle; an error-free run is healthy (with results) or empty
// coverage (no results), both of which still count as coverage.
func classifySource(h SourceHealth, contributed int) SourceState {
	if h.Skipped || h.Errors > 0 {
		return SourceFailed
	}
	if contributed == 0 {
		return SourceEmpty
	}
	return SourceHealthy
}

// HealthFromStatistics converts subfinder per-source statistics into the
// SourceHealth inputs of BuildSnapshot. selectedNames lists every source the
// run was configured to use; a source missing from statistics is reported as
// failed because it never completed.
func HealthFromStatistics(selectedNames []string, stats map[string]subscraping.Statistics) []SourceHealth {
	health := make([]SourceHealth, 0, len(selectedNames))
	for _, name := range selectedNames {
		s, ok := stats[name]
		if !ok {
			health = append(health, SourceHealth{Name: name, Errors: 1})
			continue
		}
		health = append(health, SourceHealth{
			Name:    name,
			Errors:  s.Errors,
			Results: s.Results,
			Skipped: s.Skipped,
		})
	}
	return health
}

// hostMap returns a host -> record index for O(1) lookups.
func (s *Snapshot) hostMap() map[string]HostRecord {
	out := make(map[string]HostRecord, len(s.Hosts))
	for _, host := range s.Hosts {
		out[host.Host] = host
	}
	return out
}

func (s *Snapshot) failedSourceSet() map[string]struct{} {
	out := make(map[string]struct{})
	for _, source := range s.Sources {
		if source.State == SourceFailed {
			out[source.Name] = struct{}{}
		}
	}
	return out
}
