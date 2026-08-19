// Package stats collects runtime statistics from the supervisor for troubleshooting.
package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

// AccessEntry records a single intercepted syscall with its verdict.
type AccessEntry struct {
	Timestamp time.Time
	Action    string
	Path      string
	Verdict   string // "allow" or "deny"
	Rule      string
}

// Collector gathers runtime statistics from the supervisor. All methods are
// safe for concurrent use.
type Collector struct {
	startTime time.Time

	// Counters.
	totalRequests atomic.Int64
	totalAllows   atomic.Int64
	totalDenies   atomic.Int64
	reloadCount   atomic.Int64
	cacheHits     atomic.Int64
	cacheMisses   atomic.Int64

	// Size sources for the in-memory tables. May be nil.
	decisionCacheSize   SizeFunc
	processTableSize    SizeFunc
	processTableLookups LookupFunc

	// Per-action counters.
	actionAllows sync.Map // action string -> *atomic.Int64
	actionDenies sync.Map // action string -> *atomic.Int64

	// Recent accesses ring buffer (includes both allows and denies).
	recentMu   sync.Mutex
	recent     []AccessEntry
	recentHead int

	// Recent denies ring buffer (denies only).
	deniesMu   sync.Mutex
	denies     []AccessEntry
	deniesHead int
}

const maxRecent = 40

// NewCollector creates a stats collector.
func NewCollector() *Collector {
	return &Collector{
		startTime: time.Now(),
		recent:    make([]AccessEntry, 0, maxRecent),
		denies:    make([]AccessEntry, 0, maxRecent),
	}
}

// RecordAllow records an allowed syscall.
func (c *Collector) RecordAllow(action, path, rule string) {
	c.totalRequests.Add(1)
	c.totalAllows.Add(1)
	c.getActionCounter(&c.actionAllows, action).Add(1)
	c.recordRecent(AccessEntry{
		Timestamp: time.Now(),
		Action:    action,
		Path:      path,
		Verdict:   "allow",
		Rule:      rule,
	})
}

// RecordDeny records a denied syscall.
func (c *Collector) RecordDeny(action, path, rule string) {
	c.totalRequests.Add(1)
	c.totalDenies.Add(1)
	c.getActionCounter(&c.actionDenies, action).Add(1)
	entry := AccessEntry{
		Timestamp: time.Now(),
		Action:    action,
		Path:      path,
		Verdict:   "deny",
		Rule:      rule,
	}
	c.recordRecent(entry)
	c.recordDeny(entry)
}

// RecordReload increments the policy reload counter.
func (c *Collector) RecordReload() {
	c.reloadCount.Add(1)
}

// RecordCacheHit increments the cache hit counter.
func (c *Collector) RecordCacheHit() {
	c.cacheHits.Add(1)
}

// RecordCacheMiss increments the cache miss counter.
func (c *Collector) RecordCacheMiss() {
	c.cacheMisses.Add(1)
}

// SizeFunc reports the entry count, capacity and estimated bytes of an
// in-memory table.
type SizeFunc func() (entries, capacity, bytes int)

// LookupFunc reports how many lookups found an entry and how many did not.
type LookupFunc func() (found, notFound int64)

// SetDecisionCacheFunc registers the size source for the policy decision cache.
// Hit and miss counters come from the collector's own counters, since the
// handler reports them.
func (c *Collector) SetDecisionCacheFunc(fn SizeFunc) {
	c.decisionCacheSize = fn
}

// SetProcessTableFunc registers the size and lookup-outcome sources for the
// process table. The lookup source may be nil, in which case the table is
// reported without hit counters.
func (c *Collector) SetProcessTableFunc(size SizeFunc, lookups LookupFunc) {
	c.processTableSize = size
	c.processTableLookups = lookups
}

// Summary returns current statistics snapshot.
func (c *Collector) Summary() *rpc.SummaryResponse {
	r := &rpc.SummaryResponse{
		Uptime:        time.Since(c.startTime).Truncate(time.Second).String(),
		UptimeSeconds: int64(time.Since(c.startTime).Seconds()),
		TotalRequests: c.totalRequests.Load(),
		TotalAllows:   c.totalAllows.Load(),
		TotalDenies:   c.totalDenies.Load(),
		ReloadCount:   c.reloadCount.Load(),
		ActionAllows:  make(map[string]int64),
		ActionDenies:  make(map[string]int64),
	}

	if c.decisionCacheSize != nil {
		entries, capacity, bytes := c.decisionCacheSize()
		r.Caches = append(r.Caches, rpc.CacheStats{
			Name:        rpc.CacheDecisions,
			Entries:     entries,
			Capacity:    capacity,
			Bytes:       bytes,
			Hits:        c.cacheHits.Load(),
			Misses:      c.cacheMisses.Load(),
			HitsTracked: true,
		})
	}
	if c.processTableSize != nil {
		entries, capacity, bytes := c.processTableSize()
		s := rpc.CacheStats{
			Name:     rpc.CacheProcesses,
			Entries:  entries,
			Capacity: capacity,
			Bytes:    bytes,
		}
		if c.processTableLookups != nil {
			// For this table a hit means the pid had a recorded identity, so the
			// audit record did not have to fall back on /proc.
			s.Hits, s.Misses = c.processTableLookups()
			s.HitsTracked = true
		}
		r.Caches = append(r.Caches, s)
	}

	c.actionAllows.Range(func(key, value any) bool {
		r.ActionAllows[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	c.actionDenies.Range(func(key, value any) bool {
		r.ActionDenies[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})

	return r
}

// RecentAccesses returns the N most recent accesses, newest first.
func (c *Collector) RecentAccesses(n int) []AccessEntry {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()

	size := len(c.recent)
	if size == 0 {
		return nil
	}
	if n <= 0 || n > size {
		n = size
	}

	result := make([]AccessEntry, 0, n)
	pos := c.recentHead - 1
	if size < maxRecent {
		pos = size - 1
	}
	for i := 0; i < n; i++ {
		if pos < 0 {
			pos = size - 1
		}
		result = append(result, c.recent[pos])
		pos--
	}
	return result
}

// recordRecent appends an entry to the ring buffer.
func (c *Collector) recordRecent(entry AccessEntry) {
	c.recentMu.Lock()
	if len(c.recent) < maxRecent {
		c.recent = append(c.recent, entry)
	} else {
		c.recent[c.recentHead] = entry
		c.recentHead = (c.recentHead + 1) % maxRecent
	}
	c.recentMu.Unlock()
}

// recordDeny appends an entry to the denies ring buffer.
func (c *Collector) recordDeny(entry AccessEntry) {
	c.deniesMu.Lock()
	if len(c.denies) < maxRecent {
		c.denies = append(c.denies, entry)
	} else {
		c.denies[c.deniesHead] = entry
		c.deniesHead = (c.deniesHead + 1) % maxRecent
	}
	c.deniesMu.Unlock()
}

// RecentDenies returns the N most recent denied accesses, newest first.
func (c *Collector) RecentDenies(n int) []AccessEntry {
	c.deniesMu.Lock()
	defer c.deniesMu.Unlock()

	size := len(c.denies)
	if size == 0 {
		return nil
	}
	if n <= 0 || n > size {
		n = size
	}

	result := make([]AccessEntry, 0, n)
	pos := c.deniesHead - 1
	if size < maxRecent {
		pos = size - 1
	}
	for i := 0; i < n; i++ {
		if pos < 0 {
			pos = size - 1
		}
		result = append(result, c.denies[pos])
		pos--
	}
	return result
}

// getActionCounter gets or creates an atomic counter for an action.
func (c *Collector) getActionCounter(m *sync.Map, action string) *atomic.Int64 {
	if v, ok := m.Load(action); ok {
		return v.(*atomic.Int64)
	}
	v := &atomic.Int64{}
	actual, _ := m.LoadOrStore(action, v)
	return actual.(*atomic.Int64)
}
