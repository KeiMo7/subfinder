package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// LoadReport reads a persisted delta report. Malformed content is reported as
// a CorruptionError naming the exact report file.
func (s *Store) LoadReport(domain, cycle string) (*Report, error) {
	path := s.ReportPath(domain, cycle)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report Report
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&report); err != nil {
		return nil, &CorruptionError{Domain: domain, Cycle: cycle, Path: path, Err: err}
	}
	return &report, nil
}

// ListReportCycles returns the cycles for which a delta report exists,
// chronologically ordered. Directory entries only — no report bodies are read.
func (s *Store) ListReportCycles(domain string) ([]string, error) {
	dir := filepath.Join(s.domainDir(domain), "reports")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	cycles := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".delta.json") {
			continue
		}
		cycles = append(cycles, strings.TrimSuffix(name, ".delta.json"))
	}
	slices.Sort(cycles)
	return cycles, nil
}

// Trend accumulates cycle-over-cycle counts into an ordered trend, answering
// whether an asset class keeps growing or is converging. It reads only the
// requested window of persisted reports (each one JSON document), so cost is
// bounded by the window, not the total history. A corrupted report inside the
// window is surfaced as a CorruptionError identifying the bad cycle.
func (s *Store) Trend(domain string, maxCycles int) ([]TrendPoint, error) {
	if maxCycles <= 0 {
		maxCycles = defaultMaxGapCycles
	}
	cycles, err := s.ListReportCycles(domain)
	if err != nil {
		return nil, err
	}
	if len(cycles) > maxCycles {
		cycles = cycles[len(cycles)-maxCycles:]
	}

	points := make([]TrendPoint, 0, len(cycles))
	for _, cycle := range cycles {
		report, err := s.LoadReport(domain, cycle)
		if err != nil {
			return nil, err
		}
		points = append(points, TrendPoint{
			Cycle:        cycle,
			Total:        len(report.Persistent) + len(report.New) + len(report.Recovered),
			New:          len(report.New),
			Disappeared:  len(report.Disappeared),
			Recovered:    len(report.Recovered),
			Uncertain:    len(report.Uncertain),
			StatusChange: len(report.Status),
			Degraded:     report.Degraded,
		})
	}
	return points, nil
}
