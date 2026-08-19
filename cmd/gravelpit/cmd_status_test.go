// cmd_status_test.go tests the layout of the status output.
package main

import (
	"strings"
	"testing"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

// The cache block must name each table on its own row, show memory, and print
// "-" where a table has no hit counters instead of a misleading zero.
func TestWriteSummaryCacheRows(t *testing.T) {
	s := &rpc.SummaryResponse{
		Uptime: "23s",
		Caches: []rpc.CacheStats{
			{Name: rpc.CacheDecisions, Entries: 228, Capacity: 10000, Bytes: 63488,
				Hits: 777, Misses: 222, HitsTracked: true},
			{Name: rpc.CacheProcesses, Entries: 84, Capacity: 4096, Bytes: 9216},
		},
	}

	var b strings.Builder
	writeSummary(&b, s)
	out := b.String()

	var decisions, processes string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, rpc.CacheDecisions):
			decisions = line
		case strings.HasPrefix(line, rpc.CacheProcesses):
			processes = line
		}
	}
	if decisions == "" || processes == "" {
		t.Fatalf("missing cache rows in output:\n%s", out)
	}

	for _, want := range []string{"228/10000", "62 KiB", "777", "222", "77.8%"} {
		if !strings.Contains(decisions, want) {
			t.Errorf("decisions row %q missing %q", decisions, want)
		}
	}
	for _, want := range []string{"84/4096", "9.0 KiB"} {
		if !strings.Contains(processes, want) {
			t.Errorf("processes row %q missing %q", processes, want)
		}
	}
	// Three placeholders: hits, misses, hit rate.
	if got := strings.Count(processes, "-"); got != 3 {
		t.Errorf("processes row %q has %d placeholders, want 3", processes, got)
	}
	if strings.Contains(processes, "0.0%") {
		t.Errorf("processes row %q reports a hit rate, want a placeholder", processes)
	}
}

// A summary with no cache stats must not print the block at all.
func TestWriteSummaryWithoutCaches(t *testing.T) {
	var b strings.Builder
	writeSummary(&b, &rpc.SummaryResponse{Uptime: "1s"})
	if strings.Contains(b.String(), "CACHE") {
		t.Errorf("cache block printed without stats:\n%s", b.String())
	}
}
