// SPDX-License-Identifier: MIT

/*
Package diff provides cycle-over-cycle incremental comparison for subfinder
enumeration results.

# Model

Each enumeration cycle for a target domain is persisted as one Snapshot:

	<DiffDir>/<domain>/snapshots/<cycle>.json
	<DiffDir>/<domain>/reports/<cycle>.delta.json

Cycles default to ISO year-week identifiers (e.g. 2026-W47), so a weekly
Monday schedule gets stable, sortable cycles and a re-run of the same week
overwrites the same files atomically.

A Snapshot stores the normalized host identity, the sorted source set that
reported each host, the per-host resolution status, and the health of every
selected source (healthy / empty / failed). Reports classify every host into
new, disappeared, persistent, recovered or uncertain, plus a separate list of
resolution-status transitions.

# Disappearance versus not-scanned

A host missing in the current cycle is only called "disappeared" when every
source that previously reported it ran successfully this cycle and still did
not report it. If any covering source failed, the host is "uncertain": the
run did not cover it, and asserting disappearance would be wrong. This makes
a whole-source outage degrade the result instead of manufacturing noise.

# Recovery and back-fill

When a source fails for one or more consecutive cycles and then recovers, a
host it alone covered is classified as "recovered", never "new". The report
names the last cycle that saw the host (MissingSince) and every intermediate
cycle that missed it solely because of source failures (GapCycles), so the
operator can back-fill the missing weeks. The history window inspected for
recovery is bounded (LoadWindow / MaxGapCycles); reads never load the full
history at once.

# Determinism and durability

Hosts, sources and all report slices are sorted before serialization, so the
same pair of cycles always produces an identical report. Snapshot and report
writes go through a temp-file + fsync + rename sequence in the same
directory, guaranteeing an atomic replacement: a killed process leaves
either the old complete file or the new complete file, never a truncated one.
Each cycle is an independent file, so corruption is localized to one cycle
and reported as a CorruptionError with its exact path and impact scope.

# Opt-in

The enumeration engine never calls this package unless the diff option is
enabled. Default output, exit codes and source configuration are unchanged,
and no diff files are created when the switch is off.
*/
package diff
