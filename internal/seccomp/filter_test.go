// filter_test.go tests the BPF filter builder for structural correctness.
package seccomp

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestInterceptedSyscallCount(t *testing.T) {
	// 3 open variants + 7 destructive + 4 metadata + 2 exec + 1 connect = 17 (update if changed)
	got := len(InterceptedSyscalls())
	if got != 19 {
		t.Errorf("InterceptedSyscalls() has %d entries, expected 19", got)
	}
}

func TestDeniedSyscallCount(t *testing.T) {
	got := len(DeniedSyscalls())
	if got != 1 {
		t.Errorf("DeniedSyscalls() has %d entries, expected 1", got)
	}
}

func TestBuildFilterStructure(t *testing.T) {
	filter := BuildFilter()

	if len(filter) == 0 {
		t.Fatal("filter is empty")
	}

	// First instruction loads arch (offset 4).
	if filter[0].Code != (bpfLD|bpfW|bpfABS) || filter[0].K != 4 {
		t.Errorf("first instruction should load arch at offset 4, got code=%#x k=%d", filter[0].Code, filter[0].K)
	}

	// Second instruction is the arch comparison against AUDIT_ARCH_X86_64.
	if filter[1].Code != (bpfJMP|bpfJEQ|bpfK) || filter[1].K != auditArchX86_64 {
		t.Errorf("second instruction should compare arch, got code=%#x k=%#x", filter[1].Code, filter[1].K)
	}

	// On arch mismatch, should jump to the allow at the end.
	lastIdx := len(filter) - 1
	archJumpTarget := 2 + int(filter[1].Jf) // index 2 (next instruction) + jf offset
	if archJumpTarget != lastIdx {
		t.Errorf("arch mismatch should jump to allow at index %d, goes to %d", lastIdx, archJumpTarget)
	}

	// Third instruction loads syscall number (offset 0).
	if filter[2].Code != (bpfLD|bpfW|bpfABS) || filter[2].K != 0 {
		t.Errorf("third instruction should load nr at offset 0")
	}

	// Fourth instruction checks x32 bit.
	if filter[3].Code != (bpfJMP|bpfJSET|bpfK) || filter[3].K != x32Bit {
		t.Errorf("fourth instruction should check x32 bit")
	}

	// On x32 bit set, should jump to the allow at the end.
	x32JumpTarget := 4 + int(filter[3].Jt) // index 4 + jt offset
	if x32JumpTarget != lastIdx {
		t.Errorf("x32 set should jump to allow at index %d, goes to %d", lastIdx, x32JumpTarget)
	}

	// Last instruction is ALLOW.
	if filter[lastIdx].Code != (bpfRET|bpfK) || filter[lastIdx].K != seccompRetAllow {
		t.Errorf("last instruction should be RET ALLOW")
	}
}

func TestBuildFilterInterceptedReturnsUserNotif(t *testing.T) {
	filter := BuildFilter()
	for _, nr := range InterceptedSyscalls() {
		if !findReturnForSyscall(filter, nr, seccompRetUserNotif) {
			t.Errorf("syscall %d should return USER_NOTIF", nr)
		}
	}
}

func TestBuildFilterDeniedReturnsErrno(t *testing.T) {
	filter := BuildFilter()
	expectedRet := seccompRetErrno | uint32(unix.ENOSYS)
	for _, nr := range DeniedSyscalls() {
		if !findReturnForSyscall(filter, nr, expectedRet) {
			t.Errorf("syscall %d should return ERRNO(ENOSYS)", nr)
		}
	}
}

// findReturnForSyscall checks that a JEQ for the given syscall number
// is followed by a RET with the expected value.
func findReturnForSyscall(filter []SockFilter, nr uint32, expectedRet uint32) bool {
	for i, inst := range filter {
		if inst.Code == (bpfJMP|bpfJEQ|bpfK) && inst.K == nr && inst.Jt == 0 && inst.Jf == 1 {
			if i+1 < len(filter) {
				ret := filter[i+1]
				if ret.Code == (bpfRET|bpfK) && ret.K == expectedRet {
					return true
				}
			}
		}
	}
	return false
}
