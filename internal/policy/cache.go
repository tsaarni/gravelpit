// cache.go implements a thread-safe LRU cache for policy decisions.
package policy

import (
	"container/list"
	"fmt"
	"sync"
	"unsafe"
)

// CacheKey identifies a unique policy evaluation input.
type CacheKey struct {
	Action Action
	Target string // path, socket path, or host:port
}

// cacheEntry pairs a key with its cached decision.
type cacheEntry struct {
	key      CacheKey
	decision Decision
}

// Cache is a thread-safe LRU cache for policy decisions.
type Cache struct {
	mu       sync.Mutex
	capacity int
	items    map[CacheKey]*list.Element
	order    *list.List // front = most recently used
}

// NewCache creates an LRU cache with the given maximum number of entries. A
// capacity below one is raised to one. Eviction runs before every insert, so a
// zero capacity already behaves like one, but Capacity() would report a number
// the cache does not honour.
func NewCache(capacity int) *Cache {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache{
		capacity: capacity,
		items:    make(map[CacheKey]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get looks up a cached decision. Returns the decision and true on hit, or
// zero Decision and false on miss.
func (c *Cache) Get(key CacheKey) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return Decision{}, false
	}
	c.order.MoveToFront(elem)
	return elem.Value.(*cacheEntry).decision, true
}

// Put stores a decision in the cache, evicting the least recently used entry
// if the cache is full.
func (c *Cache) Put(key CacheKey, decision Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		elem.Value.(*cacheEntry).decision = decision
		return
	}

	if c.order.Len() >= c.capacity {
		c.evict()
	}

	entry := &cacheEntry{key: key, decision: decision}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

// Clear removes all entries from the cache. Call on policy reload.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[CacheKey]*list.Element, c.capacity)
	c.order.Init()
}

// Len returns the number of entries currently in the cache.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Capacity returns the maximum number of entries the cache can hold.
func (c *Cache) Capacity() int {
	return c.capacity
}

// cacheEntryOverhead is the fixed cost of holding one entry: the entry struct,
// the list element that orders it, and the map slot that finds it. The map slot
// is estimated as key plus pointer divided by the load factor the runtime aims
// for, because Go does not expose the real figure.
const cacheEntryOverhead = int(unsafe.Sizeof(cacheEntry{})) +
	int(unsafe.Sizeof(list.Element{})) +
	(int(unsafe.Sizeof(CacheKey{}))+pointerBytes)*10/7

// pointerBytes is the size of a pointer on this platform.
const pointerBytes = int(unsafe.Sizeof(uintptr(0)))

// Stats returns the entry count, the capacity, and an estimate of the bytes
// held. All three come from one critical section so they describe the same
// moment.
//
// The byte figure walks every entry, so it is only for the status command, not
// for the syscall path. Counting bytes as entries are inserted would put the
// work on the hot path instead.
//
// It is an estimate: map overhead is approximated, and only the strings that are
// allocated per entry are counted. Action, Verdict and Errno are enum-like
// values pointing at literals in the binary, and Message often points at the
// rule's own text, so their bytes are shared rather than per entry.
func (c *Cache) Stats() (entries, capacity, bytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		e := elem.Value.(*cacheEntry)
		bytes += cacheEntryOverhead + len(e.key.Target)
		if e.decision.Rule == nil || e.decision.Message != e.decision.Rule.Message {
			// Interpolated messages are built per decision, so they are held by
			// this entry alone.
			bytes += len(e.decision.Message)
		}
	}

	return c.order.Len(), c.capacity, bytes
}

// evict removes the least recently used entry. Must be called with mu held.
func (c *Cache) evict() {
	back := c.order.Back()
	if back == nil {
		return
	}
	c.order.Remove(back)
	delete(c.items, back.Value.(*cacheEntry).key)
}

// MakeCacheKey builds a CacheKey from an event.
func MakeCacheKey(ev *Event) CacheKey {
	target := ev.Path
	if target == "" && ev.Socket != "" {
		target = ev.Socket
	}
	if target == "" && ev.Host != "" {
		target = fmt.Sprintf("%s:%d", ev.Host, ev.Port)
	}
	return CacheKey{Action: ev.Action, Target: target}
}
