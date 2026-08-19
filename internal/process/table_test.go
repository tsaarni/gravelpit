// table_test.go tests that the process table records post-exec identity.
package process

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestRecordExecUsesExecTarget checks that Exe comes from the exec target passed
// in, not from /proc/<pid>/exe. The pid used here is the test binary, so if the
// implementation ever reads /proc again it would record the test binary instead
// of the path given.
func TestRecordExecUsesExecTarget(t *testing.T) {
	tbl := New(128)
	tbl.RecordExec(os.Getpid(), "/bin/sh")

	entry := tbl.Lookup(os.Getpid())
	if entry == nil {
		t.Fatal("no entry recorded")
	}

	want, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("cannot resolve /bin/sh: %v", err)
	}
	if entry.Exe != want {
		t.Errorf("Exe = %q, want %q", entry.Exe, want)
	}
	if entry.Comm != filepath.Base(want) {
		t.Errorf("Comm = %q, want %q", entry.Comm, filepath.Base(want))
	}
	if entry.PPid != os.Getppid() {
		t.Errorf("PPid = %d, want %d", entry.PPid, os.Getppid())
	}

	self, err := os.Readlink("/proc/self/exe")
	if err == nil && entry.Exe == self {
		t.Errorf("Exe = %q, which is this test binary: identity was read from /proc instead of the exec target", entry.Exe)
	}
}

// TestRecordExecOverwrites checks that a second exec by the same pid replaces the
// entry. A shell that execs into the command it was asked to run keeps its pid,
// and the later binary is the one that matters.
func TestRecordExecOverwrites(t *testing.T) {
	tbl := New(128)
	tbl.RecordExec(os.Getpid(), "/first/binary")
	tbl.RecordExec(os.Getpid(), "/second/binary")

	entry := tbl.Lookup(os.Getpid())
	if entry == nil {
		t.Fatal("no entry recorded")
	}
	if entry.Exe != "/second/binary" {
		t.Errorf("Exe = %q, want /second/binary", entry.Exe)
	}
	// An overwrite must not add a second entry, otherwise a shell that execs the
	// command it was asked to run would consume two slots.
	if tbl.Len() != 1 {
		t.Errorf("Len = %d, want 1", tbl.Len())
	}
}

// TestTableEvictsOldest checks the table stays at its capacity. Entries are never
// deleted on exit, so eviction is the only thing bounding growth.
func TestTableEvictsOldest(t *testing.T) {
	const capacity = 8
	tbl := New(capacity)

	// Synthetic pids: readPPid fails for them and records PPid 0, which does not
	// matter here.
	for i := range capacity * 4 {
		tbl.RecordExec(900000+i, "/usr/bin/probe")
	}

	if tbl.Len() != capacity {
		t.Errorf("Len = %d, want %d", tbl.Len(), capacity)
	}
	if entry := tbl.Lookup(900000); entry != nil {
		t.Error("first pid still present, want evicted")
	}
	if entry := tbl.Lookup(900000 + capacity*4 - 1); entry == nil {
		t.Error("last pid missing, want present")
	}
}

// TestLookupPromotes checks a looked-up entry survives eviction. This is what
// makes a capped table safe: a process that is still making syscalls keeps its
// entry, and the entries lost belong to processes that have gone quiet.
func TestLookupPromotes(t *testing.T) {
	tbl := New(2)
	tbl.RecordExec(900001, "/usr/bin/first")
	tbl.RecordExec(900002, "/usr/bin/second")

	tbl.Lookup(900001)
	tbl.RecordExec(900003, "/usr/bin/third")

	if entry := tbl.Lookup(900001); entry == nil {
		t.Error("first pid evicted, want kept by the lookup")
	}
	if entry := tbl.Lookup(900002); entry != nil {
		t.Error("second pid present, want evicted")
	}
}

// TestRecordExecKeepsAncestorsWarm checks an exec promotes the parent chain.
// Without this the entry of a process that only spawns children, such as the
// top-level shell, ages out while it is still running and startedBy() stops
// matching it. The parent here is older than the child, so plain insertion order
// would evict the parent first.
func TestRecordExecKeepsAncestorsWarm(t *testing.T) {
	tbl := New(3)
	tbl.RecordExec(os.Getppid(), "/usr/bin/parent-binary")
	tbl.RecordExec(os.Getpid(), "/usr/bin/child-binary")

	// Two unrelated execs, enough to evict one entry.
	tbl.RecordExec(900101, "/usr/bin/other")
	tbl.RecordExec(900102, "/usr/bin/other")

	if entry := tbl.Lookup(os.Getppid()); entry == nil {
		t.Error("parent evicted, want promoted by the child's exec")
	}
	if entry := tbl.Lookup(os.Getpid()); entry != nil {
		t.Error("child present, want evicted as the least recently used entry")
	}
}

// TestTableStats checks the reported counts and the byte estimate. Comm is a
// slice of Exe, so it must not add to the total.
func TestTableStats(t *testing.T) {
	tbl := New(64)
	if entries, capacity, bytes := tbl.Stats(); entries != 0 || capacity != 64 || bytes != 0 {
		t.Fatalf("empty table Stats() = (%d, %d, %d), want (0, 64, 0)", entries, capacity, bytes)
	}

	exe := "/usr/lib/some/where/a-long-binary-name"
	tbl.RecordExec(900301, exe)

	entries, _, bytes := tbl.Stats()
	if entries != 1 {
		t.Errorf("entries = %d, want 1", entries)
	}
	if want := entryOverhead + len(exe); bytes != want {
		t.Errorf("bytes = %d, want %d (overhead %d + exe %d)", bytes, want, entryOverhead, len(exe))
	}

	// Eviction must lower the total: a full table does not keep growing.
	small := New(2)
	for i := range 10 {
		small.RecordExec(900310+i, exe)
	}
	if _, _, smallBytes := small.Stats(); smallBytes != 2*(entryOverhead+len(exe)) {
		t.Errorf("bytes at capacity 2 = %d, want %d", smallBytes, 2*(entryOverhead+len(exe)))
	}
}

// RecordObserved fills in a pid whose exec was never seen. /proc is the right
// source here, unlike at execve time: the process is already running.
func TestRecordObservedFillsMissingEntry(t *testing.T) {
	tbl := New(64)
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Skipf("cannot read /proc/self/exe: %v", err)
	}

	entry := tbl.RecordObserved(os.Getpid(), self)
	if entry == nil {
		t.Fatal("RecordObserved returned nil")
	}
	if entry.Exe != self {
		t.Errorf("Exe = %q, want %q", entry.Exe, self)
	}
	if entry.Comm != commFromExe(self) {
		t.Errorf("Comm = %q, want %q", entry.Comm, commFromExe(self))
	}
	// PPid is what makes the entry useful for ancestry, so it must be filled.
	if entry.PPid != os.Getppid() {
		t.Errorf("PPid = %d, want %d", entry.PPid, os.Getppid())
	}
	if got := tbl.Lookup(os.Getpid()); got != entry {
		t.Errorf("Lookup returned %v, want the observed entry", got)
	}
}

// An entry from RecordExec names the exec target and is authoritative, so an
// observation must not overwrite it.
func TestRecordObservedKeepsExecEntry(t *testing.T) {
	tbl := New(64)
	tbl.RecordExec(os.Getpid(), "/usr/bin/recorded-by-exec")

	entry := tbl.RecordObserved(os.Getpid(), "/usr/bin/seen-in-proc")
	if entry == nil {
		t.Fatal("RecordObserved returned nil")
	}
	if entry.Exe != "/usr/bin/recorded-by-exec" {
		t.Errorf("Exe = %q, want the exec-recorded path", entry.Exe)
	}
	if tbl.Len() != 1 {
		t.Errorf("Len = %d, want 1", tbl.Len())
	}
}

// An empty exe means the /proc read failed. Storing it would name nothing and
// would stop the next syscall from retrying.
func TestRecordObservedIgnoresEmptyExe(t *testing.T) {
	tbl := New(64)
	if entry := tbl.RecordObserved(900401, ""); entry != nil {
		t.Errorf("RecordObserved with empty exe = %v, want nil", entry)
	}
	if tbl.Len() != 0 {
		t.Errorf("Len = %d, want 0", tbl.Len())
	}
}

// The counters tell whether the capacity is too small: a miss means the audit
// record had to read /proc.
func TestLookupCounters(t *testing.T) {
	tbl := New(64)
	if found, notFound := tbl.Lookups(); found != 0 || notFound != 0 {
		t.Fatalf("fresh table Lookups() = (%d, %d), want (0, 0)", found, notFound)
	}

	tbl.RecordExec(900411, "/usr/bin/probe")
	tbl.Lookup(900411)
	tbl.Lookup(900411)
	tbl.Lookup(900412) // never recorded
	tbl.Lookup(900413) // never recorded

	found, notFound := tbl.Lookups()
	if found != 2 || notFound != 2 {
		t.Errorf("Lookups() = (%d, %d), want (2, 2)", found, notFound)
	}
}

// One notification per goroutine means an exec and an observation of the same
// pid can run at once. Whichever wins, the table must hold exactly one entry and
// stay consistent. Run with -race for this to be worth anything.
func TestRecordExecAndObservedConcurrent(t *testing.T) {
	tbl := New(64)
	pid := os.Getpid()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tbl.RecordExec(pid, "/usr/bin/recorded-by-exec")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			tbl.RecordObserved(pid, "/usr/bin/seen-in-proc")
		}()
	}
	wg.Wait()

	if tbl.Len() != 1 {
		t.Errorf("Len = %d, want 1", tbl.Len())
	}
	if entry := tbl.Lookup(pid); entry == nil {
		t.Error("no entry for pid after concurrent updates")
	}
}

func TestResolveExePath(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realbin")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linkbin")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"symlink resolved", link, real},
		{"real path unchanged", real, real},
		// A path that cannot be resolved is kept rather than dropped, so a
		// process whose binary is already deleted is still named.
		{"unresolvable kept", "/no/such/binary", "/no/such/binary"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveExePath(tc.in); got != tc.want {
				t.Errorf("resolveExePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCommFromExe(t *testing.T) {
	tests := []struct {
		exe  string
		want string
	}{
		{"/usr/bin/ssh", "ssh"},
		{"/usr/bin/git", "git"},
		// The kernel truncates comm to 15 bytes on exec, so a derived comm has
		// to truncate identically to be comparable with /proc/<pid>/comm.
		{"/usr/bin/a-very-long-binary-name", "a-very-long-bin"},
		{"/usr/bin/exactly15chars", "exactly15chars"},
		{"", ""},
		{"/", ""},
	}
	for _, tc := range tests {
		if got := commFromExe(tc.exe); got != tc.want {
			t.Errorf("commFromExe(%q) = %q, want %q", tc.exe, got, tc.want)
		}
		if len(commFromExe(tc.exe)) > commTruncate {
			t.Errorf("commFromExe(%q) longer than %d bytes", tc.exe, commTruncate)
		}
	}
}

// TestLookupAncestors checks the parent chain resolves to recorded entries. It
// uses the real pid/ppid of the test process so the PPid read from /proc links
// the two entries.
func TestLookupAncestors(t *testing.T) {
	tbl := New(128)
	tbl.RecordExec(os.Getppid(), "/usr/bin/parent-binary")
	tbl.RecordExec(os.Getpid(), "/usr/bin/child-binary")

	ancestors := tbl.LookupAncestors(os.Getpid())
	if len(ancestors) == 0 {
		t.Fatal("no ancestors found")
	}
	if ancestors[0].Exe != "/usr/bin/parent-binary" {
		t.Errorf("ancestors[0].Exe = %q, want /usr/bin/parent-binary", ancestors[0].Exe)
	}

	// An unrecorded pid has no ancestry rather than a partial chain.
	if got := tbl.LookupAncestors(999999); len(got) != 0 {
		t.Errorf("ancestors of unrecorded pid = %v, want empty", got)
	}
}
