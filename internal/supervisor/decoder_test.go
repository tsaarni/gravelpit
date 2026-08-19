// decoder_test.go tests syscall argument decoding and path resolution.
package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDirfdArg checks that a dirfd is recovered from the raw syscall register.
//
// The kernel copies the register verbatim into seccomp_data.args. Userspace
// loads a negative int constant with a 32-bit move, so AT_FDCWD arrives
// zero-extended as 0x00000000FFFFFF9C rather than sign-extended. Decoding it
// with a plain int() conversion yields 4294967196, the AT_FDCWD check fails, and
// every relative path is left unresolved.
func TestDirfdArg(t *testing.T) {
	tests := []struct {
		name string
		raw  uint64
		want int
	}{
		{"AT_FDCWD zero-extended", 0x00000000FFFFFF9C, atFdcwd},
		{"AT_FDCWD sign-extended", 0xFFFFFFFFFFFFFF9C, atFdcwd},
		{"stdin", 0, 0},
		{"ordinary fd", 7, 7},
		{"high fd", 1023, 1023},
		{"minus one zero-extended", 0x00000000FFFFFFFF, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dirfdArg(tt.raw); got != tt.want {
				t.Errorf("dirfdArg(0x%x) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

// TestFlagsArg checks the same truncation applies to flag arguments.
func TestFlagsArg(t *testing.T) {
	if got := flagsArg(0x00000000FFFFFFFF); got != -1 {
		t.Errorf("flagsArg(0xFFFFFFFF) = %d, want -1", got)
	}
	if got := flagsArg(uint64(unix.O_WRONLY | unix.O_CREAT)); got != unix.O_WRONLY|unix.O_CREAT {
		t.Errorf("flagsArg(O_WRONLY|O_CREAT) = %#o, want %#o", got, unix.O_WRONLY|unix.O_CREAT)
	}
}

// TestResolveSyscallPathAbsolute checks an absolute path is returned unchanged.
func TestResolveSyscallPathAbsolute(t *testing.T) {
	got, err := ResolveSyscallPath(uint32(os.Getpid()), atFdcwd, "/etc/passwd")
	if err != nil {
		t.Fatalf("ResolveSyscallPath: %v", err)
	}
	if got != "/etc/passwd" {
		t.Errorf("got %q, want %q", got, "/etc/passwd")
	}
}

// TestResolveSyscallPathCwd checks a relative path with AT_FDCWD becomes
// absolute. A relative path must never reach policy matching.
func TestResolveSyscallPathCwd(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	for _, rel := range []string{"file.txt", "./file.txt", "sub/file.txt"} {
		got, err := ResolveSyscallPath(uint32(os.Getpid()), atFdcwd, rel)
		if err != nil {
			t.Fatalf("ResolveSyscallPath(%q): %v", rel, err)
		}
		if !filepath.IsAbs(got) {
			t.Errorf("ResolveSyscallPath(%q) = %q, want absolute", rel, got)
		}
		if want := filepath.Join(cwd, rel); got != want {
			t.Errorf("ResolveSyscallPath(%q) = %q, want %q", rel, got, want)
		}
	}
}

// TestResolveSyscallPathDirfd checks resolution relative to a real dirfd.
func TestResolveSyscallPathDirfd(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open %s: %v", dir, err)
	}
	defer func() { _ = f.Close() }()

	got, err := ResolveSyscallPath(uint32(os.Getpid()), int(f.Fd()), "file.txt")
	if err != nil {
		t.Fatalf("ResolveSyscallPath: %v", err)
	}
	if want := filepath.Join(dir, "file.txt"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveSyscallPathEmpty checks an empty path is reported unresolved rather
// than silently becoming the base directory, and that it is distinguishable from
// a genuine resolution failure. The handler answers empty paths with ENOENT (what
// the kernel returns) instead of a policy denial, so the two must not be
// conflated.
func TestResolveSyscallPathEmpty(t *testing.T) {
	_, err := ResolveSyscallPath(uint32(os.Getpid()), atFdcwd, "")
	if !errors.Is(err, ErrUnresolved) {
		t.Errorf("err = %v, want ErrUnresolved", err)
	}
	if !errors.Is(err, ErrEmptyPath) {
		t.Errorf("err = %v, want ErrEmptyPath", err)
	}
}

// TestOtherFailuresAreNotEmptyPath checks resolution failures that are not an
// empty path do not carry ErrEmptyPath. Misclassifying one would answer a real
// decoding failure with ENOENT and skip the denial.
func TestOtherFailuresAreNotEmptyPath(t *testing.T) {
	cases := []struct {
		name  string
		dirfd int
		path  string
	}{
		{"negative dirfd", -7, "rel.txt"},
		{"unknown dirfd", 999999, "rel.txt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveSyscallPath(uint32(os.Getpid()), tc.dirfd, tc.path)
			if !errors.Is(err, ErrUnresolved) {
				t.Fatalf("err = %v, want ErrUnresolved", err)
			}
			if errors.Is(err, ErrEmptyPath) {
				t.Errorf("err = %v, must not match ErrEmptyPath", err)
			}
		})
	}
}

// TestResolveSyscallPathBadDirfd checks a dirfd that is neither AT_FDCWD nor a
// valid fd is reported unresolved instead of yielding a relative path.
func TestResolveSyscallPathBadDirfd(t *testing.T) {
	// A negative value other than AT_FDCWD is invalid.
	if _, err := ResolveSyscallPath(uint32(os.Getpid()), -7, "rel.txt"); !errors.Is(err, ErrUnresolved) {
		t.Errorf("negative dirfd: err = %v, want ErrUnresolved", err)
	}
	// A closed or never-opened fd has no /proc entry.
	if _, err := ResolveSyscallPath(uint32(os.Getpid()), 999999, "rel.txt"); !errors.Is(err, ErrUnresolved) {
		t.Errorf("unknown dirfd: err = %v, want ErrUnresolved", err)
	}
}

// TestResolveSyscallPathNonPathFd checks an fd that is not a filesystem path is
// rejected. /proc reads these back as "socket:[n]" or "pipe:[n]", which must
// never be joined onto.
func TestResolveSyscallPathNonPathFd(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer func() { _ = unix.Close(fds[0]) }()
	defer func() { _ = unix.Close(fds[1]) }()

	_, err := ResolveSyscallPath(uint32(os.Getpid()), fds[0], "rel.txt")
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("err = %v, want ErrUnresolved", err)
	}
	if !strings.Contains(err.Error(), "not a filesystem path") {
		t.Errorf("err = %v, want a not-a-filesystem-path reason", err)
	}
}

// TestResolveSyscallPathDeletedDir checks a dirfd whose directory was removed is
// rejected. The kernel appends " (deleted)" to the /proc link; joining onto that
// yields a path that cannot exist but could still match a policy pattern.
func TestResolveSyscallPathDeletedDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "gp-deleted-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}

	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := os.Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err = ResolveSyscallPath(uint32(os.Getpid()), int(f.Fd()), "rel.txt")
	if !errors.Is(err, ErrUnresolved) {
		t.Errorf("err = %v, want ErrUnresolved", err)
	}
}

// TestResolveSyscallPathLiterallyNamedDeleted checks a directory whose name ends
// in " (deleted)" still resolves. The suffix alone does not prove deletion, so
// st_nlink is what decides.
func TestResolveSyscallPathLiterallyNamedDeleted(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "cache (deleted)")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := ResolveSyscallPath(uint32(os.Getpid()), int(f.Fd()), "file.txt")
	if err != nil {
		t.Fatalf("ResolveSyscallPath: %v", err)
	}
	if want := filepath.Join(dir, "file.txt"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestReadTgid checks the thread group leader is read for the current process,
// where tid equals tgid.
func TestReadTgid(t *testing.T) {
	pid := uint32(os.Getpid())
	got, ok := readTgid(pid)
	if !ok {
		t.Fatal("readTgid returned not ok")
	}
	if got != pid {
		t.Errorf("readTgid = %d, want %d", got, pid)
	}
}

// TestReadCwd checks the cwd is read and no default is substituted on failure.
func TestReadCwd(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	got, ok := ReadCwd(uint32(os.Getpid()))
	if !ok {
		t.Fatal("ReadCwd returned not ok")
	}
	if got != want {
		t.Errorf("ReadCwd = %q, want %q", got, want)
	}

	if _, ok := ReadCwd(0); ok {
		t.Error("ReadCwd(0) returned ok, want failure rather than a default")
	}
}

// TestResolveFdPath checks an fd resolves to its own path, as needed by
// execveat with AT_EMPTY_PATH.
func TestResolveFdPath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(file, []byte("x"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := ResolveFdPath(uint32(os.Getpid()), int(f.Fd()))
	if err != nil {
		t.Fatalf("ResolveFdPath: %v", err)
	}
	if got != file {
		t.Errorf("got %q, want %q", got, file)
	}
}
