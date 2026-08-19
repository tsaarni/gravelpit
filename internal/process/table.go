// Package process maintains a table of running processes built from execve notifications.
//
// Design decisions:
//   - The table does NOT walk /proc on every syscall to reconstruct ancestry.
//     Reading the parent chain at decision time is both expensive and wrong: when
//     an intermediate process exits, the child is reparented to init, so the chain
//     truncates and startedBy("git") fails intermittently for anything that
//     daemonizes. Recording the relationship at exec time keeps it correct.
//   - Gravelpit does NOT set PR_SET_CHILD_SUBREAPER. It does not need to: one
//     notif fd covers every process using the filter regardless of reparenting.
//     Setting it breaks programs that wait on their own process groups (e.g.
//     bazel's client double-forks to daemonize its server, and a subreaper adopts
//     the intermediate child causing wait to fail with ECHILD).
//   - Identity comes from the exec target in the syscall, not from /proc. At
//     execve notification time the exec has not happened yet, so /proc still
//     describes the calling program. See RecordExec. The one exception is
//     RecordObserved, which runs while handling some other syscall, long after
//     any exec finished, and is the only way to name a process whose exec was
//     never seen.
//   - argv is not recorded. /proc/<pid>/cmdline at exec time is the caller's
//     argv, not the new program's, so it was removed rather than kept wrong.
//     Populating it correctly means decoding the argv array from the syscall.
//   - Exe and startedBy are weak identity checks, fine for attribution, not for
//     enforcement.
//   - Entries are never deleted on process exit, because exit is not
//     intercepted and an entry has to outlive its process: ancestry is walked
//     through the table, so dropping an exited parent would truncate the chain
//     and startedBy() would start missing. Growth is bounded by LRU eviction
//     instead. A pid whose entry was evicted behaves like one that never exec'd
//     inside the sandbox: audit records fall back to reading /proc for exe.
package process

import (
	"container/list"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

// Entry holds info about a process recorded at execve time.
type Entry struct {
	PID  int
	Exe  string // exec target, symlink-resolved to match /proc/<pid>/exe
	Comm string // derived from Exe the way the kernel derives comm
	PPid int    // from /proc/<pid>/status at exec time
}

// maxAncestorDepth bounds every walk of the parent chain. A depth limit is used
// instead of a visited set so the walk allocates nothing: it runs on the exec
// path and on the deny path.
const maxAncestorDepth = 64

// Table tracks processes by pid, built from execve notifications. Entries are
// held in LRU order and the oldest is evicted once capacity is reached.
//
// The lock is exclusive rather than a RWMutex because lookups reorder the LRU.
// That reordering is what keeps eviction safe: a process stays in the table for
// as long as it is seen, so the entries lost are the ones belonging to processes
// that have gone quiet, which are also the ones most likely to have exited. The
// critical section is a map lookup plus a list splice.
type Table struct {
	mu       sync.Mutex
	capacity int
	entries  map[int]*list.Element
	order    *list.List // front = most recently used, value is *Entry

	// Lookup outcomes, for reporting. Guarded by mu, which Lookup already holds,
	// so they cost nothing beyond the increment.
	found    int64
	notFound int64
}

// New creates an empty process table holding at most capacity entries. A
// capacity below one is raised to one so the field cannot claim a size the table
// does not honour; eviction runs before every insert, so zero would already
// behave like one.
func New(capacity int) *Table {
	if capacity < 1 {
		capacity = 1
	}
	return &Table{
		capacity: capacity,
		entries:  make(map[int]*list.Element, capacity),
		order:    list.New(),
	}
}

// put stores an entry as most recently used, evicting the least recently used
// one when full. A pid that is already present is overwritten: a shell that
// execs the command it was asked to run keeps its pid, and the later binary is
// the one that matters. Must be called with mu held.
func (t *Table) put(entry *Entry) {
	if elem, ok := t.entries[entry.PID]; ok {
		t.order.MoveToFront(elem)
		elem.Value = entry
		return
	}

	if t.order.Len() >= t.capacity {
		if back := t.order.Back(); back != nil {
			t.order.Remove(back)
			delete(t.entries, back.Value.(*Entry).PID)
		}
	}

	t.entries[entry.PID] = t.order.PushFront(entry)
}

// get returns the entry for a pid and marks it most recently used. Must be
// called with mu held.
func (t *Table) get(pid int) *Entry {
	elem, ok := t.entries[pid]
	if !ok {
		return nil
	}
	t.order.MoveToFront(elem)
	return elem.Value.(*Entry)
}

// RecordExec stores the identity the process will have once the exec completes.
// exePath is the exec target taken from the decoded syscall.
//
// The exe must not be read from /proc here. The notification arrives before the
// kernel performs the exec, so /proc/<pid>/{exe,cmdline,comm} still describe the
// calling program. Reading them named the wrong binary for every exec'd process:
// a child that git forked and then exec'd ssh was recorded as git, and because
// ancestry is built from these entries every ancestor name was shifted one exec
// back, so startedBy("git") never matched ssh while startedBy("gravelpit") did.
//
// PPid is still read from /proc because exec does not change it.
//
// Call this only for an exec that policy allowed. A denied exec never happens,
// and recording it would name a binary the process never became.
func (t *Table) RecordExec(pid int, exePath string) {
	ppid, err := readPPid(pid)
	if err != nil {
		slog.Debug("process table: failed to read ppid", "pid", pid, "error", err)
		ppid = 0
	}

	exe := resolveExePath(exePath)

	t.mu.Lock()
	t.put(&Entry{
		PID:  pid,
		Exe:  exe,
		Comm: commFromExe(exe),
		PPid: ppid,
	})
	// Promote the ancestors of this pid as well. Without this the entries of a
	// process that only spawns children, such as the top-level shell, would age
	// out and be evicted while it is still running, which is exactly the entry
	// startedBy() needs.
	t.touchAncestors(ppid)
	t.mu.Unlock()
}

// touchAncestors marks the parent chain starting at pid as recently used. Must
// be called with mu held.
func (t *Table) touchAncestors(pid int) {
	for depth := 0; depth < maxAncestorDepth; depth++ {
		entry := t.get(pid)
		if entry == nil || entry.PPid == pid {
			return
		}
		pid = entry.PPid
	}
}

// RecordObserved fills in an entry for a pid whose exec was never seen, from a
// live /proc read, and returns the entry now held for that pid.
//
// Reading /proc is correct here, unlike in RecordExec: this runs while handling
// some other syscall, so the exec is long finished and /proc/<pid>/exe names the
// binary the process is really running. For a process that forked and has not
// exec'd yet it names the inherited parent binary, which is also what it is
// running until it execs.
//
// An existing entry is kept rather than replaced. An entry from RecordExec is
// authoritative because it names the exec target, and an observation must not
// overwrite it. This is checked twice: before the /proc read to skip it when the
// pid is already known, and again afterwards because the lock is released while
// reading, so a concurrent exec or a second observer may have inserted one.
//
// exePath comes from /proc/<pid>/exe, which is already resolved, so it is stored
// as given.
func (t *Table) RecordObserved(pid int, exePath string) *Entry {
	if exePath == "" {
		return nil
	}

	t.mu.Lock()
	if entry := t.get(pid); entry != nil {
		t.mu.Unlock()
		return entry
	}
	t.mu.Unlock()

	// Read outside the lock: it touches /proc and only matters for a pid the
	// table does not hold yet.
	ppid, err := readPPid(pid)
	if err != nil {
		slog.Debug("process table: failed to read ppid", "pid", pid, "error", err)
		ppid = 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// Check again: the /proc read above happened with the lock released.
	if entry := t.get(pid); entry != nil {
		return entry
	}
	entry := &Entry{
		PID:  pid,
		Exe:  exePath,
		Comm: commFromExe(exePath),
		PPid: ppid,
	}
	t.put(entry)
	t.touchAncestors(ppid)
	return entry
}

// resolveExePath resolves symlinks in the exec target so that Exe matches what// the kernel will report in /proc/<pid>/exe, which names the final binary. The
// two must agree: policy evaluation reads the live /proc value while audit
// records and ancestry read the table, and a rule on process.exe would otherwise
// match or miss depending on which source filled the field. /bin/sh and
// /usr/bin/dash are the common case.
//
// Falls back to the unresolved path when resolution fails, so a binary that is
// already gone is still named rather than becoming empty.
func resolveExePath(exePath string) string {
	if exePath == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return exePath
	}
	return resolved
}

// commTruncate is the kernel's TASK_COMM_LEN minus the NUL terminator. The
// kernel truncates comm to this length on exec, so a derived comm must match to
// be comparable with /proc/<pid>/comm.
const commTruncate = 15

// commFromExe derives the process comm from the binary path the way the kernel
// does on exec: the basename, truncated to 15 bytes.
func commFromExe(exe string) string {
	comm := filepath.Base(exe)
	if comm == "." || comm == "/" {
		return ""
	}
	if len(comm) > commTruncate {
		comm = comm[:commTruncate]
	}
	return comm
}

// Lookup returns the entry for a pid, or nil if not found. The lookup counts as
// use, so an active process is not evicted, and is counted for reporting.
func (t *Table) Lookup(pid int) *Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.get(pid)
	if entry == nil {
		t.notFound++
		return nil
	}
	t.found++
	return entry
}

// Lookups returns how many Lookup calls found an entry and how many did not.
// A miss is normal rather than a fault: it means the audit record has to read
// /proc, either because the exec was never seen or because the entry was
// evicted. A rising miss count is the signal that the capacity is too small.
//
// Only Lookup is counted. The ancestor walk is a different question and would
// make these numbers describe two things at once.
func (t *Table) Lookups() (found, notFound int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.found, t.notFound
}

// Len returns the number of entries held. For diagnostics and tests.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}

// entryOverhead is the fixed cost of holding one process: the entry struct, the
// list element that orders it, and the map slot that finds it. The map slot is
// estimated as key plus pointer divided by the load factor the runtime aims for,
// because Go does not expose the real figure.
const entryOverhead = int(unsafe.Sizeof(Entry{})) +
	int(unsafe.Sizeof(list.Element{})) +
	(int(unsafe.Sizeof(int(0)))+int(unsafe.Sizeof(uintptr(0))))*10/7

// Stats returns the entry count, the capacity, and an estimate of the bytes
// held. All three come from one critical section so they describe the same
// moment.
//
// The byte figure walks every entry, so it is only for the status command, not
// for the syscall path.
//
// Comm is not counted: filepath.Base returns a slice of Exe, so it shares the
// same backing array and costs no extra bytes.
func (t *Table) Stats() (entries, capacity, bytes int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for elem := t.order.Front(); elem != nil; elem = elem.Next() {
		bytes += entryOverhead + len(elem.Value.(*Entry).Exe)
	}

	return t.order.Len(), t.capacity, bytes
}

// LookupAncestors walks the PPid chain and returns the ancestors in order from
// immediate parent to the oldest recorded ancestor. Every entry visited counts
// as use, so a live chain stays in the table.
func (t *Table) LookupAncestors(pid int) []*Entry {
	t.mu.Lock()
	defer t.mu.Unlock()

	var ancestors []*Entry
	current := pid

	for depth := 0; depth < maxAncestorDepth; depth++ {
		entry := t.get(current)
		if entry == nil || entry.PPid == current {
			break
		}
		parent := t.get(entry.PPid)
		if parent == nil {
			break
		}
		ancestors = append(ancestors, parent)
		current = entry.PPid
	}

	return ancestors
}

// readPPid reads the parent pid from /proc/<pid>/status.
// The relevant line has the format: "PPid:\t<number>".
func readPPid(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		var ppid int
		_, err := fmt.Sscanf(strings.TrimPrefix(line, "PPid:"), "%d", &ppid)
		if err != nil {
			return 0, fmt.Errorf("parsing PPid line %q: %w", line, err)
		}
		return ppid, nil
	}
	return 0, fmt.Errorf("PPid not found in /proc/%d/status", pid)
}
