// procpath_test.go tests that procfs paths are resolved against the target
// process rather than the supervisor.
package supervisor

import (
	"fmt"
	"os"
	"testing"
)

// TestCanonicalizeProcSelfUsesTarget checks that references to the caller's own
// process collapse to /proc/self, and that another process's paths stay literal.
//
// /proc/self and /dev/fd are magic links meaning "whoever reads them". Resolving
// them in the supervisor pointed policy at the supervisor's fd table, so a shell
// redirecting to /dev/fd/1 was denied. Allowing own fds must not allow every
// same-uid process's fds, so the two cases must stay distinguishable.
func TestCanonicalizeProcSelfUsesTarget(t *testing.T) {
	const target = uint32(1234)
	const other = uint32(5678)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"dev fd", "/dev/fd/1", "/proc/self/fd/1"},
		{"dev fd dir", "/dev/fd", "/proc/self/fd"},
		{"proc self", "/proc/self/fd/1", "/proc/self/fd/1"},
		{"proc thread-self", "/proc/thread-self/fd/2", "/proc/self/fd/2"},
		{"own pid", fmt.Sprintf("/proc/%d/fd/3", target), "/proc/self/fd/3"},
		{"own pid maps", fmt.Sprintf("/proc/%d/maps", target), "/proc/self/maps"},
		{"other pid stays literal", fmt.Sprintf("/proc/%d/fd/3", other), fmt.Sprintf("/proc/%d/fd/3", other)},
		{"other pid mem stays literal", fmt.Sprintf("/proc/%d/mem", other), fmt.Sprintf("/proc/%d/mem", other)},
		{"non-pid proc entry", "/proc/meminfo", "/proc/meminfo"},
		{"proc sys", "/proc/sys/kernel/hostname", "/proc/sys/kernel/hostname"},
		// /dev/fdinfo must not be mistaken for the /dev/fd prefix.
		{"dev fdinfo not matched", "/dev/fdinfo", "/dev/fdinfo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalizePathForPid(tt.in, target)
			if got != tt.want {
				t.Errorf("CanonicalizePathForPid(%q, %d) = %q, want %q", tt.in, target, got, tt.want)
			}
		})
	}
}

// TestCanonicalizeProcSelfRealPid checks the live case: a real pid referring to
// itself collapses to /proc/self, which is what makes shell fd redirection work.
func TestCanonicalizeProcSelfRealPid(t *testing.T) {
	pid := uint32(os.Getpid())

	got := CanonicalizePathForPid(fmt.Sprintf("/proc/%d/fd/1", pid), pid)
	if want := "/proc/self/fd/1"; got != want {
		t.Errorf("own pid: got %q, want %q", got, want)
	}

	// /dev/fd must not resolve to the supervisor's own fd directory.
	got = CanonicalizePathForPid("/dev/fd/1", pid)
	if want := "/proc/self/fd/1"; got != want {
		t.Errorf("/dev/fd/1: got %q, want %q", got, want)
	}
}

// TestCanonicalizeNonProcUnaffected checks ordinary paths still go through
// normal symlink canonicalization.
func TestCanonicalizeNonProcUnaffected(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/file.txt"

	got := CanonicalizePathForPid(file, uint32(os.Getpid()))
	if got != CanonicalizePath(file) {
		t.Errorf("got %q, want same as CanonicalizePath %q", got, CanonicalizePath(file))
	}
}
