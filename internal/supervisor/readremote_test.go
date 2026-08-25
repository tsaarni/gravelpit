// readremote_test.go covers reading syscall arguments from a target's memory:
// short reads near an unmapped page, and telling a failed read apart from an
// empty path argument.
package supervisor

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mapStringBeforeGuard maps two pages, writes s at the end of the first one, then
// unmaps the second. Returns the address of s.
//
// This is the layout that makes a PathMax-sized read run into unmapped memory.
func mapStringBeforeGuard(t *testing.T, s string) uintptr {
	t.Helper()

	ps := os.Getpagesize()
	need := len(s) + 1 // include the NUL
	if need > ps {
		t.Fatalf("string too long for one page: %d", need)
	}

	region, err := unix.Mmap(-1, 0, 2*ps, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	base := uintptr(unsafe.Pointer(&region[0]))

	off := ps - need
	copy(region[off:], s)
	region[ps-1] = 0

	// munmap is called directly: the x/sys/unix wrapper tracks its own mappings
	// and rejects a partial unmap.
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, base+uintptr(ps), uintptr(ps), 0); errno != 0 {
		t.Fatalf("munmap guard page: %v", errno)
	}
	t.Cleanup(func() {
		unix.Syscall(unix.SYS_MUNMAP, base, uintptr(ps), 0)
	})

	return base + uintptr(off)
}

// TestReadRemoteAcrossUnmappedPage checks a string at the end of a mapped page is
// read even though the request reaches into unmapped memory. The read is short
// rather than failing, so treating a short read as failure would turn ordinary
// paths into empty ones.
func TestReadRemoteAcrossUnmappedPage(t *testing.T) {
	const want = "/home/user/.local/state/runagent/logs/824aabc2-bc17-439b-a5c4-ea29ba6e89c8.log"
	addr := mapStringBeforeGuard(t, want)

	got := make([]byte, unix.PathMax)
	n := readRemote(uint32(os.Getpid()), addr, got)
	if n == 0 {
		t.Fatal("readRemote returned 0 bytes for a mapped string")
	}
	if n == len(got) {
		t.Fatalf("read filled the whole buffer (%d bytes): the guard page did not "+
			"limit it, so this is not the layout under test", n)
	}
	end := -1
	for i := 0; i < n; i++ {
		if got[i] == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatalf("no NUL terminator in %d bytes read", n)
	}
	if string(got[:end]) != want {
		t.Errorf("got %q, want %q", string(got[:end]), want)
	}
}

// TestReadRemoteShortString checks the ordinary case: a string well inside a
// mapped page is read unchanged.
func TestReadRemoteShortString(t *testing.T) {
	want := "/etc/hosts"
	b := append([]byte(want), 0)
	addr := uintptr(unsafe.Pointer(&b[0]))

	got := make([]byte, unix.PathMax)
	n := readRemote(uint32(os.Getpid()), addr, got)
	if n < len(b) {
		t.Fatalf("readRemote returned %d bytes, want at least %d", n, len(b))
	}
	if string(got[:len(want)]) != want {
		t.Errorf("got %q, want %q", string(got[:len(want)]), want)
	}
}

// TestReadStringFailureIsNotEmptyPath checks a failed read is reported as
// unresolved, not as an empty path. An empty path is answered with a bare ENOENT
// and no audit record, which would hide the failure.
func TestReadStringFailureIsNotEmptyPath(t *testing.T) {
	d := &Decoder{pid: uint32(os.Getpid())}

	var ev DecodedEvent
	if got := d.resolveAt(&ev, atFdcwd, "", false); got != "" {
		t.Errorf("resolveAt = %q, want empty", got)
	}
	if !ev.Unresolved {
		t.Error("ev.Unresolved = false, want true for a failed read")
	}
	if ev.EmptyPath {
		t.Error("ev.EmptyPath = true for a failed read, want false")
	}
}

// TestReadStringNullPointer checks a NULL path pointer is not a read failure:
// there is nothing to read, and the kernel rejects such a syscall itself.
func TestReadStringNullPointer(t *testing.T) {
	d := &Decoder{pid: uint32(os.Getpid())}
	s, ok := d.ReadString(0)
	if !ok {
		t.Error("ReadString ok = false for a NULL pointer, want true")
	}
	if s != "" {
		t.Errorf("ReadString = %q, want empty", s)
	}
}
