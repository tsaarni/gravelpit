package policy

import (
	"fmt"
	"sync"
	"testing"
)

func TestCacheGetMiss(t *testing.T) {
	c := NewCache(10)
	_, ok := c.Get(CacheKey{Action: ActionRead, Target: "/foo"})
	if ok {
		t.Fatal("expected miss on empty cache")
	}
}

func TestCachePutAndGet(t *testing.T) {
	c := NewCache(10)
	key := CacheKey{Action: ActionWrite, Target: "/tmp/file"}
	d := Decision{Verdict: VerdictAllow, Score: 5}

	c.Put(key, d)
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Verdict != VerdictAllow || got.Score != 5 {
		t.Fatalf("unexpected decision: %+v", got)
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(3)
	keys := []CacheKey{
		{Action: ActionRead, Target: "/a"},
		{Action: ActionRead, Target: "/b"},
		{Action: ActionRead, Target: "/c"},
	}
	for i, k := range keys {
		c.Put(k, Decision{Verdict: VerdictAllow, Score: i})
	}

	// Cache is full. Insert a 4th entry; /a should be evicted (LRU).
	c.Put(CacheKey{Action: ActionRead, Target: "/d"}, Decision{Verdict: VerdictDeny})

	if _, ok := c.Get(keys[0]); ok {
		t.Fatal("expected /a to be evicted")
	}
	// /b, /c, /d should still be present.
	for _, k := range []CacheKey{keys[1], keys[2], {Action: ActionRead, Target: "/d"}} {
		if _, ok := c.Get(k); !ok {
			t.Fatalf("expected %v to be present", k)
		}
	}
}

func TestCacheEvictionLRUOrder(t *testing.T) {
	c := NewCache(3)
	keys := []CacheKey{
		{Action: ActionRead, Target: "/a"},
		{Action: ActionRead, Target: "/b"},
		{Action: ActionRead, Target: "/c"},
	}
	for i, k := range keys {
		c.Put(k, Decision{Verdict: VerdictAllow, Score: i})
	}

	// Access /a so it becomes most recently used.
	c.Get(keys[0])

	// Insert /d; now /b should be evicted (LRU after /a was accessed).
	c.Put(CacheKey{Action: ActionRead, Target: "/d"}, Decision{Verdict: VerdictDeny})

	if _, ok := c.Get(keys[1]); ok {
		t.Fatal("expected /b to be evicted")
	}
	if _, ok := c.Get(keys[0]); !ok {
		t.Fatal("expected /a to still be present")
	}
}

func TestCacheUpdateExisting(t *testing.T) {
	c := NewCache(10)
	key := CacheKey{Action: ActionWrite, Target: "/x"}

	c.Put(key, Decision{Verdict: VerdictAllow})
	c.Put(key, Decision{Verdict: VerdictDeny})

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Verdict != VerdictDeny {
		t.Fatalf("expected updated verdict deny, got %v", got.Verdict)
	}
	if c.Len() != 1 {
		t.Fatalf("expected len 1, got %d", c.Len())
	}
}

// A capacity below one must be raised, so Capacity() reports a number the cache
// honours. Eviction runs before every insert, so the entry count is already
// limited either way; the Len check guards against that changing.
func TestCacheCapacityBelowOneIsRaised(t *testing.T) {
	for _, capacity := range []int{0, -5} {
		c := NewCache(capacity)
		if c.Capacity() != 1 {
			t.Errorf("NewCache(%d).Capacity() = %d, want 1", capacity, c.Capacity())
		}
		for i := range 100 {
			c.Put(CacheKey{Action: ActionRead, Target: fmt.Sprintf("/p/%d", i)}, Decision{Verdict: VerdictAllow})
		}
		if c.Len() != 1 {
			t.Errorf("NewCache(%d) grew to %d entries, want 1", capacity, c.Len())
		}
	}
}

// TestCacheStats checks the reported entry count and byte estimate. The byte
// figure is white-box on purpose: it is the fixed per-entry overhead plus the
// target string, which is the only part allocated per entry.
func TestCacheStats(t *testing.T) {
	c := NewCache(10)
	if entries, capacity, bytes := c.Stats(); entries != 0 || capacity != 10 || bytes != 0 {
		t.Fatalf("empty cache Stats() = (%d, %d, %d), want (0, 10, 0)", entries, capacity, bytes)
	}

	target := "/home/user/work/project/some/deep/path/file.go"
	c.Put(CacheKey{Action: ActionRead, Target: target}, Decision{Verdict: VerdictAllow})

	entries, _, bytes := c.Stats()
	if entries != 1 {
		t.Errorf("entries = %d, want 1", entries)
	}
	if want := cacheEntryOverhead + len(target); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}

	// A longer target must cost more, by exactly the extra characters.
	longer := target + "-and-some-more"
	c.Put(CacheKey{Action: ActionRead, Target: longer}, Decision{Verdict: VerdictAllow})
	_, _, bytes2 := c.Stats()
	if want := bytes + cacheEntryOverhead + len(longer); bytes2 != want {
		t.Errorf("bytes after second entry = %d, want %d", bytes2, want)
	}
}

// A message copied from the rule is shared, so it must not be counted. An
// interpolated message is built per decision and must be.
func TestCacheStatsCountsInterpolatedMessagesOnly(t *testing.T) {
	rule := &Rule{Name: "r", Message: "Writing to '${path}' is not allowed"}
	key := CacheKey{Action: ActionWrite, Target: "/etc/passwd"}

	shared := NewCache(10)
	shared.Put(key, Decision{Verdict: VerdictDeny, Rule: rule, Message: rule.Message})
	_, _, sharedBytes := shared.Stats()

	interpolated := NewCache(10)
	msg := "Writing to '/etc/passwd' is not allowed"
	interpolated.Put(key, Decision{Verdict: VerdictDeny, Rule: rule, Message: msg})
	_, _, interpolatedBytes := interpolated.Stats()

	if want := cacheEntryOverhead + len(key.Target); sharedBytes != want {
		t.Errorf("shared message: bytes = %d, want %d", sharedBytes, want)
	}
	if want := cacheEntryOverhead + len(key.Target) + len(msg); interpolatedBytes != want {
		t.Errorf("interpolated message: bytes = %d, want %d", interpolatedBytes, want)
	}
}

func TestCacheClear(t *testing.T) {
	c := NewCache(10)
	c.Put(CacheKey{Action: ActionRead, Target: "/a"}, Decision{Verdict: VerdictAllow})
	c.Put(CacheKey{Action: ActionRead, Target: "/b"}, Decision{Verdict: VerdictAllow})

	c.Clear()

	if c.Len() != 0 {
		t.Fatalf("expected empty cache after clear, got len %d", c.Len())
	}
	if _, ok := c.Get(CacheKey{Action: ActionRead, Target: "/a"}); ok {
		t.Fatal("expected miss after clear")
	}
}

func TestMakeCacheKeyFilePath(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/etc/passwd"}
	key := MakeCacheKey(ev)
	if key.Action != ActionRead || key.Target != "/etc/passwd" {
		t.Fatalf("unexpected key: %+v", key)
	}
}

func TestMakeCacheKeySocket(t *testing.T) {
	ev := &Event{Action: ActionConnect, Socket: "/var/run/docker.sock"}
	key := MakeCacheKey(ev)
	if key.Target != "/var/run/docker.sock" {
		t.Fatalf("unexpected target: %s", key.Target)
	}
}

func TestMakeCacheKeyHostPort(t *testing.T) {
	ev := &Event{Action: ActionConnect, Host: "10.0.0.1", Port: 443}
	key := MakeCacheKey(ev)
	if key.Target != "10.0.0.1:443" {
		t.Fatalf("unexpected target: %s", key.Target)
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := NewCache(100)
	var wg sync.WaitGroup

	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := CacheKey{Action: ActionRead, Target: fmt.Sprintf("/path/%d", n)}
			c.Put(key, Decision{Verdict: VerdictAllow, Score: n})
			c.Get(key)
		}(i)
	}
	wg.Wait()

	if c.Len() > 100 {
		t.Fatalf("cache exceeded capacity: %d", c.Len())
	}
}
