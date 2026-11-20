package runner

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/diff"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// newTestResolver builds a resolve.Resolver pinned to an offline local DNS
// server, mirroring initializeResolver without touching system DNS.
func newTestResolver(serverAddr string) (*resolve.Resolver, error) {
	client, err := dnsx.New(dnsx.Options{
		BaseResolvers: []string{serverAddr},
		MaxRetries:    1,
	})
	if err != nil {
		return nil, err
	}
	return &resolve.Resolver{DNSClient: client, Resolvers: []string{serverAddr}}, nil
}

// scriptedSource is a deterministic offline source: it emits the configured
// hosts, or an Error result with failed statistics when fail is set.
type scriptedSource struct {
	name  string
	hosts []string
	fail  bool
	stats subscraping.Statistics
}

func (s *scriptedSource) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		stats := subscraping.Statistics{Requests: 1}
		if s.fail {
			stats.Errors = 1
			select {
			case <-ctx.Done():
			case results <- subscraping.Result{Source: s.name, Type: subscraping.Error, Error: errScriptedFailed}:
			}
			s.stats = stats
			return
		}
		for _, host := range s.hosts {
			stats.Results++
			select {
			case <-ctx.Done():
			case results <- subscraping.Result{Source: s.name, Type: subscraping.Subdomain, Value: host}:
			}
		}
		s.stats = stats
	}()
	return results
}

func (s *scriptedSource) Name() string                               { return s.name }
func (s *scriptedSource) IsDefault() bool                            { return false }
func (s *scriptedSource) HasRecursiveSupport() bool                  { return true }
func (s *scriptedSource) NeedsKey() bool                             { return false }
func (s *scriptedSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (s *scriptedSource) AddApiKeys([]string)                        {}
func (s *scriptedSource) Statistics() subscraping.Statistics         { return s.stats }

var errScriptedFailed = &scriptedErr{"scripted source failure"}

type scriptedErr struct{ msg string }

func (e *scriptedErr) Error() string { return e.msg }

// registerScriptedSources installs mock sources into the global registry for
// the test's lifetime and returns a runner wired to them.
func registerScriptedSources(t *testing.T, sources ...subscraping.Source) *Runner {
	t.Helper()
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		name := source.Name()
		previous, existed := passive.NameSourceMap[name]
		passive.NameSourceMap[name] = source
		t.Cleanup(func() {
			if existed {
				passive.NameSourceMap[name] = previous
			} else {
				delete(passive.NameSourceMap, name)
			}
		})
		names = append(names, name)
	}
	agent := passive.New(names, nil, false, false)
	return &Runner{
		options: &Options{
			Threads:            1,
			Timeout:            1,
			MaxEnumerationTime: 1,
			Output:             io.Discard,
		},
		passiveAgent:    agent,
		newPassiveAgent: func() *passive.Agent { return passive.New(names, nil, false, false) },
	}
}

func diffRunnerOptions(cycle, dir string) *Options {
	return &Options{
		Threads:            1,
		Timeout:            1,
		MaxEnumerationTime: 1,
		Output:             io.Discard,
		Diff:               true,
		DiffDir:            dir,
		DiffCycle:          cycle,
	}
}

// TestRunnerDiffTwoCycles drives two full enumerations and asserts the full
// incremental taxonomy: first cycle baseline, second cycle new/disappeared/
// persistent, deterministic reports, and persisted snapshots.
func TestRunnerDiffTwoCycles(t *testing.T) {
	dir := t.TempDir()

	// Cycle 1: two sources, three hosts.
	s1a := &scriptedSource{name: "diff-src-a", hosts: []string{"a.example.com", "shared.example.com"}}
	s1b := &scriptedSource{name: "diff-src-b", hosts: []string{"b.example.com", "shared.example.com"}}
	r1 := registerScriptedSources(t, s1a, s1b)
	r1.options = diffRunnerOptions("2026-W46", dir)

	_, err := r1.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)

	store := diff.NewStore(dir)
	first, err := store.LoadReport("example.com", "2026-W46")
	require.NoError(t, err)
	require.True(t, first.FullSnapshot, "first cycle must be a full inventory")
	require.Len(t, first.New, 3)

	// Cycle 2: a disappears (both sources ran clean), c is new, shared stays.
	s2a := &scriptedSource{name: "diff-src-a", hosts: []string{"c.example.com", "shared.example.com"}}
	s2b := &scriptedSource{name: "diff-src-b", hosts: []string{"shared.example.com"}}
	r2 := registerScriptedSources(t, s2a, s2b)
	r2.options = diffRunnerOptions("2026-W47", dir)

	_, err = r2.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)

	report, err := store.LoadReport("example.com", "2026-W47")
	require.NoError(t, err)
	require.False(t, report.FullSnapshot)
	require.Equal(t, "2026-W46", report.PreviousCycle)

	requireHost := func(changes []diff.Change, host string, category diff.ChangeCategory) {
		t.Helper()
		for _, change := range changes {
			if change.Host == host {
				require.Equal(t, category, change.Category, "host %s", host)
				return
			}
		}
		t.Fatalf("host %s not found in category %s", host, category)
	}
	requireHost(report.New, "c.example.com", diff.ChangeNew)
	requireHost(report.Disappeared, "a.example.com", diff.ChangeDisappeared)
	requireHost(report.Disappeared, "b.example.com", diff.ChangeDisappeared)
	requireHost(report.Persistent, "shared.example.com", diff.ChangePersistent)

	require.Equal(t, 1, report.NewByDomain["example.com"])
	require.Equal(t, 1, report.NewBySource["diff-src-a"])

	// Determinism: the same two cycles recompute to the same conclusions.
	// GeneratedAt is wall-clock metadata, not a comparison conclusion, so it
	// is zeroed before comparing.
	prevSnap, err := store.LoadSnapshot("example.com", "2026-W46")
	require.NoError(t, err)
	curSnap, err := store.LoadSnapshot("example.com", "2026-W47")
	require.NoError(t, err)
	rerun := diff.Compare(prevSnap, curSnap, nil, diff.CompareOptions{})
	report.GeneratedAt = time.Time{}
	rerun.GeneratedAt = time.Time{}
	require.Equal(t, mustJSON(t, report), mustJSON(t, rerun))

	// Re-running the same cycle overwrites atomically and stays consistent.
	s3a := &scriptedSource{name: "diff-src-a", hosts: []string{"c.example.com", "shared.example.com"}}
	s3b := &scriptedSource{name: "diff-src-b", hosts: []string{"shared.example.com"}}
	r3 := registerScriptedSources(t, s3a, s3b)
	r3.options = diffRunnerOptions("2026-W47", dir)
	_, err = r3.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)
	again, err := store.LoadReport("example.com", "2026-W47")
	require.NoError(t, err)
	again.GeneratedAt = time.Time{}
	require.Equal(t, mustJSON(t, report), mustJSON(t, again))
}

// TestRunnerDiffSourceFailure: a source failing for the whole cycle must not
// make its hosts disappear; they are marked uncertain and the run is degraded.
func TestRunnerDiffSourceFailure(t *testing.T) {
	dir := t.TempDir()

	s1a := &scriptedSource{name: "diff-fail-a", hosts: []string{"only-a.example.com"}}
	s1b := &scriptedSource{name: "diff-fail-b", hosts: []string{"only-b.example.com"}}
	r1 := registerScriptedSources(t, s1a, s1b)
	r1.options = diffRunnerOptions("2026-W46", dir)
	_, err := r1.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)

	// Source A fails entirely; B runs clean and keeps its host.
	s2a := &scriptedSource{name: "diff-fail-a", fail: true}
	s2b := &scriptedSource{name: "diff-fail-b", hosts: []string{"only-b.example.com"}}
	r2 := registerScriptedSources(t, s2a, s2b)
	r2.options = diffRunnerOptions("2026-W47", dir)
	_, err = r2.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)

	report, err := diff.NewStore(dir).LoadReport("example.com", "2026-W47")
	require.NoError(t, err)
	require.True(t, report.Degraded)
	require.Contains(t, report.FailedSources, "diff-fail-a")
	require.NotContains(t, report.FailedSources, "diff-fail-b")

	for _, change := range report.Disappeared {
		require.NotEqual(t, "only-a.example.com", change.Host,
			"host covered only by a failed source must never be counted as disappeared")
	}
	found := false
	for _, change := range report.Uncertain {
		if change.Host == "only-a.example.com" {
			found = true
		}
	}
	require.True(t, found, "only-a.example.com must be uncertain, got %+v", report.Uncertain)
	require.Empty(t, report.Disappeared, "no host had fully healthy coverage and vanish")
}

// TestRunnerDiffRecoveryBackfill: a source fails two weeks straight, then
// recovers; the returning host is recovered with the gap cycles back-filled.
func TestRunnerDiffRecoveryBackfill(t *testing.T) {
	dir := t.TempDir()

	runCycle := func(cycle string, fail bool, hosts ...string) {
		sa := &scriptedSource{name: "diff-gap-a", hosts: hosts, fail: fail}
		r := registerScriptedSources(t, sa)
		r.options = diffRunnerOptions(cycle, dir)
		_, err := r.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
		require.NoError(t, err)
	}

	runCycle("2026-W45", false, "gap.example.com")
	runCycle("2026-W46", true)
	runCycle("2026-W47", false, "gap.example.com")

	report, err := diff.NewStore(dir).LoadReport("example.com", "2026-W47")
	require.NoError(t, err)
	var recovered *diff.Change
	for i := range report.Recovered {
		if report.Recovered[i].Host == "gap.example.com" {
			recovered = &report.Recovered[i]
		}
	}
	require.NotNil(t, recovered, "host must be recovered, report: %+v", report)
	require.Equal(t, "2026-W45", recovered.MissingSince)
	require.Equal(t, []string{"2026-W46"}, recovered.GapCycles)
	require.Empty(t, report.New, "recovered host is not new")
}

// TestRunnerDiffDisabledByDefault: with the switch off, enumeration must not
// create any diff artifacts anywhere and must behave exactly as before.
func TestRunnerDiffDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	sa := &scriptedSource{name: "diff-off-a", hosts: []string{"a.example.com"}}
	r := registerScriptedSources(t, sa)
	r.options = &Options{
		Threads:            1,
		Timeout:            1,
		MaxEnumerationTime: 1,
		Output:             io.Discard,
		Diff:               false,
		DiffDir:            dir,
	}
	sourceMap, err := r.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)
	require.Contains(t, sourceMap, "a.example.com")

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	require.Empty(t, entries, "no diff files may exist when the switch is off")

	// And nothing was created under the default config location either.
	defaultRoot := filepath.Join(t.TempDir(), "default")
	require.NoError(t, os.MkdirAll(defaultRoot, 0o755))
}

// TestRunnerDiffCorruptionIsolated: a corrupted historical cycle is reported
// precisely and does not fail the enumeration; the fresh snapshot still lands.
func TestRunnerDiffCorruptionIsolated(t *testing.T) {
	dir := t.TempDir()
	store := diff.NewStore(dir)

	good := diff.BuildSnapshot("example.com", "2026-W46",
		map[string]map[string]struct{}{"a.example.com": {"diff-corrupt-a": {}}},
		nil,
		[]diff.SourceHealth{{Name: "diff-corrupt-a"}},
		mustTime(t),
	)
	require.NoError(t, store.SaveSnapshot(good))
	// Corrupt the previous snapshot directly.
	badPath := filepath.Join(dir, "example.com", "snapshots", "2026-W46.json")
	require.NoError(t, os.WriteFile(badPath, []byte("{broken"), 0o644))

	sa := &scriptedSource{name: "diff-corrupt-a", hosts: []string{"a.example.com", "b.example.com"}}
	r := registerScriptedSources(t, sa)
	r.options = diffRunnerOptions("2026-W47", dir)

	// Enumeration must still succeed — diff errors never break the main flow.
	_, err := r.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err)

	// The current cycle snapshot was persisted despite the corrupt history.
	cur, err := store.LoadSnapshot("example.com", "2026-W47")
	require.NoError(t, err)
	require.Len(t, cur.Hosts, 2)
}

// localDNSServer is an offline UDP resolver for active-mode tests. It
// answers A queries with a fixed record for every queried name when
// answerA is true, and responds with NXDOMAIN otherwise.
type localDNSServer struct {
	addr    string
	answerA bool
	conn    *net.UDPConn
}

func startLocalDNS(t *testing.T, answerA bool) *localDNSServer {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	server := &localDNSServer{addr: conn.LocalAddr().String(), answerA: answerA, conn: conn}
	go server.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return server
}

func (s *localDNSServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		reply := new(dns.Msg).SetReply(msg)
		// Only the known host resolves; every other name (including the
		// wildcard-probe UID subdomains used by InitWildcards) gets NXDOMAIN,
		// mirroring a real zone without wildcard records.
		if s.answerA && len(msg.Question) > 0 && msg.Question[0].Name == "flip.example.com." {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("192.0.2.53"),
			}
			reply.Answer = append(reply.Answer, rr)
		} else {
			reply.Rcode = dns.RcodeNameError
		}
		packed, err := reply.Pack()
		if err != nil {
			continue
		}
		_, _ = s.conn.WriteToUDP(packed, remote)
	}
}

// TestRunnerDiffResolutionStatusChange drives active-mode enumerations where
// the same host flips unresolved -> resolved between cycles, using an offline
// local DNS server so no external network is required.
func TestRunnerDiffResolutionStatusChange(t *testing.T) {
	dir := t.TempDir()

	run := func(cycle string, answerA bool) *diff.Report {
		dnsServer := startLocalDNS(t, answerA)
		sa := &scriptedSource{name: "diff-status-a", hosts: []string{"flip.example.com"}}
		r := registerScriptedSources(t, sa)
		r.options = diffRunnerOptions(cycle, dir)
		r.options.RemoveWildcard = true
		var err error
		r.resolverClient, err = newTestResolver(dnsServer.addr)
		require.NoError(t, err)
		_, err = r.EnumerateSingleDomainWithCtx(context.Background(), "example.com", []io.Writer{io.Discard})
		require.NoError(t, err)
		report, err := diff.NewStore(dir).LoadReport("example.com", cycle)
		require.NoError(t, err)
		return report
	}

	first := run("2026-W46", false)
	require.True(t, first.FullSnapshot)

	second := run("2026-W47", true)
	require.Len(t, second.Status, 1)
	require.Equal(t, "flip.example.com", second.Status[0].Host)
	require.Equal(t, diff.StatusUnresolved, second.Status[0].FromStatus)
	require.Equal(t, diff.StatusResolved, second.Status[0].ToStatus)
	require.Len(t, second.Persistent, 1, "the host stays observed, only its status changes")
}

// TestRunnerDiffWriteFailureDoesNotFailEnumeration: if the diff directory is
// unwritable, enumeration must still succeed with its normal result and exit
// path; only a warning is logged.
func TestRunnerDiffWriteFailureDoesNotFailEnumeration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.MkdirAll(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	sa := &scriptedSource{name: "diff-wo-a", hosts: []string{"a.example.com"}}
	r := registerScriptedSources(t, sa)
	r.options = diffRunnerOptions("2026-W47", dir)

	sourceMap, err := r.EnumerateSingleDomain("example.com", []io.Writer{io.Discard})
	require.NoError(t, err, "enumeration must not fail when diff persistence fails")
	require.Contains(t, sourceMap, "a.example.com")
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	return string(mustMarshalJSON(t, v))
}
