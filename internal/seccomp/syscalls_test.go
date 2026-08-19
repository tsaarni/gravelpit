// syscalls_test.go checks the syscall name table stays in step with the filter.
package seccomp

import (
	"sort"
	"strings"
	"testing"
)

// Every intercepted syscall reaches the supervisor and ends up named in audit
// records and in the syscall CEL variable. A syscall added to the filter without
// a name here would surface as syscall_<nr>, which no rule can match.
func TestEveryInterceptedSyscallHasAName(t *testing.T) {
	for _, nr := range InterceptedSyscalls() {
		name := SyscallName(int(nr))
		if strings.HasPrefix(name, "syscall_") {
			t.Errorf("intercepted syscall %d has no name: got %q", nr, name)
		}
	}
}

func TestSyscallNameNumberRoundTrip(t *testing.T) {
	for _, name := range SyscallNames() {
		nr, ok := SyscallNumber(name)
		if !ok {
			t.Errorf("SyscallNumber(%q) not found, but the name is listed", name)
			continue
		}
		if got := SyscallName(nr); got != name {
			t.Errorf("round trip of %q gave %q via number %d", name, got, nr)
		}
	}
}

// An unknown number is reported rather than dropped, because seeing an
// unexpected syscall number is itself worth knowing.
func TestSyscallNameUnknown(t *testing.T) {
	if got := SyscallName(999999); got != "syscall_999999" {
		t.Errorf("SyscallName(999999) = %q, want syscall_999999", got)
	}
	if _, ok := SyscallNumber("no-such-syscall"); ok {
		t.Error("SyscallNumber accepted a name that is not a syscall")
	}
}

// The list is used in a user-facing error message, so the order has to be stable.
func TestSyscallNamesSorted(t *testing.T) {
	names := SyscallNames()
	if len(names) == 0 {
		t.Fatal("no syscall names")
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("names are not sorted: %v", names)
	}
}
