// Package diff implements cycle-over-cycle incremental comparison of
// subfinder enumeration results.
//
// The package is opt-in: the single-run enumeration flow never touches it
// unless the diff option is enabled. A per-cycle Snapshot (one JSON document
// per target domain and cycle, written atomically) is the persisted identity
// used to classify hosts as new, disappeared, persistent, recovered or
// uncertain across cycles, together with per-source health and per-host
// resolution status.
package diff

import (
	"strings"
	"time"
)

// SourceState describes the outcome of one source for a single cycle.
type SourceState string

const (
	// SourceHealthy means the source ran and reported at least one host.
	SourceHealthy SourceState = "healthy"
	// SourceEmpty means the source ran without transport errors but returned
	// no hosts. It is still treated as providing coverage.
	SourceEmpty SourceState = "empty"
	// SourceFailed means the source was unavailable for the whole cycle
	// (transport/parse errors, skipped because of missing credentials, or
	// never executed). A failed source provides no coverage and its hosts
	// must never be classified as disappeared.
	SourceFailed SourceState = "failed"
)

// HostStatus records the resolution status of a host in a cycle.
type HostStatus string

const (
	// StatusUnknown is used when no active resolution was performed
	// (passive enumeration without -active/-nW).
	StatusUnknown HostStatus = "unknown"
	// StatusResolved means the host answered DNS in the cycle.
	StatusResolved HostStatus = "resolved"
	// StatusUnresolved means the host was observed but did not resolve.
	StatusUnresolved HostStatus = "unresolved"
)

// ChangeCategory is the cycle-over-cycle classification of a host.
type ChangeCategory string

const (
	// ChangeNew: host first observed in the current cycle with no evidence
	// of a prior observation.
	ChangeNew ChangeCategory = "new"
	// ChangeDisappeared: host observed in a previous healthy cycle and not
	// observed in the current one, with every source that previously
	// reported it healthy and still not reporting it.
	ChangeDisappeared ChangeCategory = "disappeared"
	// ChangePersistent: host observed in both compared cycles.
	ChangePersistent ChangeCategory = "persistent"
	// ChangeRecovered: host missing in one or more intermediate cycles
	// because the only sources covering it had failed, and observed again
	// once coverage recovered. It is never reported as new.
	ChangeRecovered ChangeCategory = "recovered"
	// ChangeUncertain: host not observed in the current cycle, but at least
	// one source previously reporting it had failed, so disappearance cannot
	// be asserted ("not scanned this round", not "gone").
	ChangeUncertain ChangeCategory = "uncertain"
)

// SnapshotFormatVersion is the on-disk format version of Snapshot.
const SnapshotFormatVersion = 1

// HostRecord is the normalized, per-host identity persisted for a cycle.
type HostRecord struct {
	// Host is the normalized FQDN: lower-cased, trailing dot removed.
	Host string `json:"host"`
	// Sources is the sorted, de-duplicated set of sources that reported the
	// host in this cycle.
	Sources []string `json:"sources"`
	// Resolved is the per-host resolution status for the cycle.
	Resolved HostStatus `json:"resolved"`
}

// SourceRecord captures source health for a cycle.
type SourceRecord struct {
	Name   string      `json:"name"`
	State  SourceState `json:"state"`
	Errors int         `json:"errors"`
	// Results is the number of (deduplicated) hosts the source contributed.
	Results int `json:"results"`
}

// Snapshot is the full persisted result of one cycle for one domain.
type Snapshot struct {
	// FormatVersion allows safe evolution of the on-disk layout.
	FormatVersion int `json:"format_version"`
	// Domain is the normalized target domain the enumeration ran against.
	Domain string `json:"domain"`
	// Cycle is the identifier of the enumeration cycle (ISO year-week by
	// default, e.g. 2026-W47).
	Cycle string `json:"cycle"`
	// GeneratedAt is the UTC timestamp at which the snapshot was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// Sources holds one record per source selected for the run.
	Sources []SourceRecord `json:"sources"`
	// Hosts holds one record per observed host, sorted by Host so that the
	// serialization of identical data is byte-stable.
	Hosts []HostRecord `json:"hosts"`
}

// Change describes a single host's classification between two cycles.
type Change struct {
	Host       string         `json:"host"`
	Category   ChangeCategory `json:"category"`
	FromStatus HostStatus     `json:"from_status,omitempty"`
	ToStatus   HostStatus     `json:"to_status,omitempty"`
	Sources    []string       `json:"sources,omitempty"`
	// MissingSince is the last cycle in which a recovered host was seen
	// before the gap (only set for recovered).
	MissingSince string `json:"missing_since,omitempty"`
	// GapCycles lists the intermediate cycles in which the host was not
	// observed solely because its covering sources had failed (only set for
	// recovered).
	GapCycles []string `json:"gap_cycles,omitempty"`
	// Reason explains uncertain classifications for operators.
	Reason string `json:"reason,omitempty"`
}

// StatusChange describes a host whose resolution status changed while it
// remained observed (e.g. unresolved -> resolved).
type StatusChange struct {
	Host       string     `json:"host"`
	FromStatus HostStatus `json:"from_status"`
	ToStatus   HostStatus `json:"to_status"`
}

// Report is the deterministic result of comparing two cycles.
type Report struct {
	FormatVersion int       `json:"format_version"`
	Domain        string    `json:"domain"`
	PreviousCycle string    `json:"previous_cycle,omitempty"`
	CurrentCycle  string    `json:"current_cycle"`
	GeneratedAt   time.Time `json:"generated_at"`
	// FullSnapshot is false when no previous snapshot exists. In that case
	// the report contains only the full current inventory and no delta.
	FullSnapshot bool `json:"full_snapshot"`
	// FailedSources are the sources that were unavailable in the current
	// cycle, making any disappearance attributed to them uncertain.
	FailedSources []string `json:"failed_sources,omitempty"`
	// Degraded is true when at least one selected source failed this cycle.
	Degraded bool `json:"degraded"`

	New         []Change       `json:"new"`
	Disappeared []Change       `json:"disappeared"`
	Persistent  []Change       `json:"persistent"`
	Recovered   []Change       `json:"recovered,omitempty"`
	Uncertain   []Change       `json:"uncertain,omitempty"`
	Status      []StatusChange `json:"status_changes,omitempty"`

	// NewBySource counts new hosts per contributing source.
	NewBySource map[string]int `json:"new_by_source,omitempty"`
	// NewByDomain counts new hosts per registrable target domain.
	NewByDomain map[string]int `json:"new_by_domain,omitempty"`
}

// TrendPoint is one cycle in the accumulated multi-cycle trend.
type TrendPoint struct {
	Cycle        string `json:"cycle"`
	Total        int    `json:"total"`
	New          int    `json:"new"`
	Disappeared  int    `json:"disappeared"`
	Recovered    int    `json:"recovered"`
	Uncertain    int    `json:"uncertain"`
	StatusChange int    `json:"status_change"`
	Degraded     bool   `json:"degraded"`
}

// normalizeHost returns the canonical identity used for every comparison:
// lower-case, whitespace and the FQDN trailing dot removed. Two raw values
// that differ only in case or a trailing dot therefore map to the same host.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(host)), ".")
}
