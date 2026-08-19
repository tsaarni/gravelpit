// collector_test.go tests the summary the status command renders.
package stats

import (
	"testing"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

// Both tables must appear separately, each with its own counters. For the
// process table a hit means the pid had a recorded identity, so the audit record
// did not have to read /proc.
func TestSummaryReportsBothTables(t *testing.T) {
	c := NewCollector()
	c.SetDecisionCacheFunc(func() (int, int, int) { return 12, 100, 3400 })
	c.SetProcessTableFunc(
		func() (int, int, int) { return 5, 64, 900 },
		func() (int64, int64) { return 40, 10 },
	)
	c.RecordCacheHit()
	c.RecordCacheHit()
	c.RecordCacheMiss()

	s := c.Summary()
	if len(s.Caches) != 2 {
		t.Fatalf("got %d cache entries, want 2", len(s.Caches))
	}

	decisions := s.Cache(rpc.CacheDecisions)
	if decisions == nil {
		t.Fatal("no decision cache stats")
	}
	if decisions.Entries != 12 || decisions.Capacity != 100 || decisions.Bytes != 3400 {
		t.Errorf("decisions = %+v, want entries 12, capacity 100, bytes 3400", decisions)
	}
	if !decisions.HitsTracked || decisions.Hits != 2 || decisions.Misses != 1 {
		t.Errorf("decisions hits = %d, misses = %d, tracked = %v, want 2, 1, true",
			decisions.Hits, decisions.Misses, decisions.HitsTracked)
	}

	processes := s.Cache(rpc.CacheProcesses)
	if processes == nil {
		t.Fatal("no process table stats")
	}
	if processes.Entries != 5 || processes.Capacity != 64 || processes.Bytes != 900 {
		t.Errorf("processes = %+v, want entries 5, capacity 64, bytes 900", processes)
	}
	if !processes.HitsTracked || processes.Hits != 40 || processes.Misses != 10 {
		t.Errorf("processes hits = %d, misses = %d, tracked = %v, want 40, 10, true",
			processes.Hits, processes.Misses, processes.HitsTracked)
	}
}

// The lookup source is optional: without it the table is reported without hit
// counters rather than with zeros that would read as "never found".
func TestSummaryProcessTableWithoutLookupCounters(t *testing.T) {
	c := NewCollector()
	c.SetProcessTableFunc(func() (int, int, int) { return 5, 64, 900 }, nil)

	processes := c.Summary().Cache(rpc.CacheProcesses)
	if processes == nil {
		t.Fatal("no process table stats")
	}
	if processes.HitsTracked {
		t.Error("HitsTracked = true, want false when no lookup source is registered")
	}
}

// A collector with no registered sources must report no tables rather than rows
// of zeros, so the status output does not claim a cache that is not there.
func TestSummaryWithoutSources(t *testing.T) {
	s := NewCollector().Summary()
	if len(s.Caches) != 0 {
		t.Errorf("got %d cache entries, want 0", len(s.Caches))
	}
	if s.Cache(rpc.CacheDecisions) != nil {
		t.Error("Cache() returned stats for an unregistered table")
	}
}
