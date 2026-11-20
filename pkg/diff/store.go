package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// CorruptionError identifies an unreadable historical segment and the scope
// of its impact. Each cycle is an independent file, so a corrupted cycle can
// be pinpointed and isolated without discarding the rest of the history.
type CorruptionError struct {
	Domain string
	Cycle  string
	Path   string
	Err    error
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("diff history corrupted for domain %q cycle %q at %s: %v (deltas touching this cycle are unavailable; other cycles are unaffected)",
		e.Domain, e.Cycle, e.Path, e.Err)
}

func (e *CorruptionError) Unwrap() error { return e.Err }

// ErrNoHistory is returned when no previous snapshot exists for a domain. The
// caller must then emit a full inventory instead of a delta.
var ErrNoHistory = errors.New("no previous diff snapshot found; only a full inventory can be produced for this cycle")

// Store persists per-domain, per-cycle snapshots on the local filesystem.
type Store struct {
	root string
}

// NewStore opens a store rooted at root. The directory tree is created lazily
// on the first write so that merely enabling reads never creates artifacts.
func NewStore(root string) *Store {
	return &Store{root: filepath.Clean(root)}
}

// Root returns the store root directory.
func (s *Store) Root() string { return s.root }

func (s *Store) domainDir(domain string) string {
	return filepath.Join(s.root, normalizeHost(domain))
}

func (s *Store) snapshotPath(domain, cycle string) string {
	return filepath.Join(s.domainDir(domain), "snapshots", cycle+".json")
}

// ReportPath returns the location of a cycle's delta report.
func (s *Store) ReportPath(domain, cycle string) string {
	return filepath.Join(s.domainDir(domain), "reports", cycle+".delta.json")
}

// SaveSnapshot writes a snapshot atomically: bytes are fully rendered and
// fsynced in a sibling temp file, then renamed into place. A process killed
// mid-write leaves either the previous complete file or the new complete
// file, never a truncated one.
func (s *Store) SaveSnapshot(snapshot *Snapshot) error {
	if snapshot == nil || snapshot.Domain == "" || snapshot.Cycle == "" {
		return errors.New("snapshot requires a domain and a cycle")
	}
	target := s.snapshotPath(snapshot.Domain, snapshot.Cycle)
	return atomicWriteJSON(target, snapshot)
}

// SaveReport writes a delta report with the same atomicity guarantees.
func (s *Store) SaveReport(report *Report) error {
	if report == nil || report.Domain == "" || report.CurrentCycle == "" {
		return errors.New("report requires a domain and a cycle")
	}
	target := s.ReportPath(report.Domain, report.CurrentCycle)
	return atomicWriteJSON(target, report)
}

func atomicWriteJSON(target string, value any) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create diff directory %s: %w", dir, err)
	}

	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode diff payload for %s: %w", target, err)
	}
	payload = append(payload, '\n')

	// The temp file must live in the same directory for rename(2) to be
	// atomic on the same filesystem.
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create diff temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := io.Copy(tmp, bytes.NewReader(payload)); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write diff temp file %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync diff temp file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close diff temp file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return fmt.Errorf("rename diff temp file to %s: %w", target, err)
	}
	return nil
}

// LoadSnapshot reads a single cycle. A missing file returns an fs error the
// caller can test with os.IsNotExist; malformed content is reported as a
// CorruptionError naming the exact cycle file.
func (s *Store) LoadSnapshot(domain, cycle string) (*Snapshot, error) {
	path := s.snapshotPath(domain, cycle)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	snapshot, err := decodeSnapshot(domain, cycle, path, data)
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func decodeSnapshot(domain, cycle, path string, data []byte) (*Snapshot, error) {
	var snapshot Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&snapshot); err != nil {
		return nil, &CorruptionError{Domain: domain, Cycle: cycle, Path: path, Err: err}
	}
	if snapshot.FormatVersion != SnapshotFormatVersion {
		return nil, &CorruptionError{
			Domain: domain,
			Cycle:  cycle,
			Path:   path,
			Err:    fmt.Errorf("unsupported snapshot format version %d (supported %d)", snapshot.FormatVersion, SnapshotFormatVersion),
		}
	}
	if snapshot.Domain == "" || snapshot.Cycle == "" {
		return nil, &CorruptionError{
			Domain: domain,
			Cycle:  cycle,
			Path:   path,
			Err:    errors.New("snapshot is missing domain or cycle"),
		}
	}
	return &snapshot, nil
}

// ListCycles returns the stored cycles for a domain in chronological order.
// Only directory entries are read, not snapshot bodies, so the cost is
// independent of history size.
func (s *Store) ListCycles(domain string) ([]string, error) {
	dir := filepath.Join(s.domainDir(domain), "snapshots")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	cycles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		cycles = append(cycles, strings.TrimSuffix(entry.Name(), ".json"))
	}
	slices.Sort(cycles)
	return cycles, nil
}

// LatestCycle returns the most recent stored cycle or "" when history is
// empty. A corrupted latest file is reported rather than silently skipped so
// the operator learns which segment is unreadable.
func (s *Store) LatestCycle(domain string) (string, error) {
	cycles, err := s.ListCycles(domain)
	if err != nil {
		return "", err
	}
	if len(cycles) == 0 {
		return "", nil
	}
	return cycles[len(cycles)-1], nil
}

// LoadPrevious returns the snapshot immediately before the given cycle. It
// lets callers select an arbitrary comparison window without loading the
// whole history. ErrNoHistory is returned when the domain has no earlier
// cycle.
func (s *Store) LoadPrevious(domain, cycle string) (*Snapshot, error) {
	cycles, err := s.ListCycles(domain)
	if err != nil {
		return nil, err
	}
	idx, _ := slices.BinarySearch(cycles, cycle)
	// idx is the insertion point: walk backwards past the current cycle and
	// any duplicates.
	for idx > 0 {
		idx--
		if cycles[idx] == cycle {
			continue
		}
		return s.LoadSnapshot(domain, cycles[idx])
	}
	return nil, ErrNoHistory
}

// LoadWindow returns at most limit snapshots ending at (and excluding) the
// given cycle, oldest first. It is the bounded-history accessor used for
// gap recovery and trend accumulation: callers decide how many cycles are
// needed and never deserialize the full history. A corrupted cycle inside
// the window aborts with the precise CorruptionError.
func (s *Store) LoadWindow(domain, cycle string, limit int) ([]*Snapshot, error) {
	if limit <= 0 {
		return nil, nil
	}
	cycles, err := s.ListCycles(domain)
	if err != nil {
		return nil, err
	}
	idx, _ := slices.BinarySearch(cycles, cycle)
	start := idx - limit
	if start < 0 {
		start = 0
	}
	out := make([]*Snapshot, 0, idx-start)
	for _, c := range cycles[start:idx] {
		snapshot, err := s.LoadSnapshot(domain, c)
		if err != nil {
			return nil, err
		}
		out = append(out, snapshot)
	}
	return out, nil
}
