// Package seccomp builds the BPF filter that routes intercepted syscalls to userspace.
//
// The filter is immutable once installed. It cannot be changed for a running
// sandbox, and policy cannot widen it. So the filter must cover everything any
// policy might ever want to decide, independent of what current policy actually
// uses. The CEL policy decides what is allowed; the BPF filter only decides what
// reaches the policy engine.
//
// The BPF is built by hand from sock_filter instructions (a flat list of
// syscall-number comparisons), so libseccomp is not needed and there is no cgo
// dependency.
package seccomp

import "golang.org/x/sys/unix"

// InterceptedSyscalls returns the set of syscall numbers the filter routes
// to userspace via SECCOMP_RET_USER_NOTIF. Everything not listed here is
// SECCOMP_RET_ALLOW and never reaches the policy engine.
func InterceptedSyscalls() []uint32 {
	return []uint32{
		// File content access: read/write intent is determined from flags.
		// open is included even though glibc and Go both use openat on x86_64,
		// because "no current libc uses it" is not a durable property.
		unix.SYS_OPEN,
		unix.SYS_OPENAT,
		unix.SYS_OPENAT2,

		// Destructive operations: deletion never calls open, so without these
		// rm -rf ~/ proceeds with no notification. rename destroys the
		// destination if it exists, so it is checked for both source and dest.
		// ftruncate is excluded because its fd came from an open already checked.
		unix.SYS_UNLINK,
		unix.SYS_UNLINKAT,
		unix.SYS_RMDIR,
		unix.SYS_RENAME,
		unix.SYS_RENAMEAT,
		unix.SYS_RENAMEAT2,
		unix.SYS_TRUNCATE,
		unix.SYS_MKDIR,
		unix.SYS_MKDIRAT,

		// Metadata: intercepted to deliver "this is policy, chmod will not help"
		// when the agent gets EACCES and reaches for chmod. Not a data-loss risk,
		// not a bypass (the open is still mediated).
		unix.SYS_CHMOD,
		unix.SYS_FCHMODAT,
		unix.SYS_CHOWN,
		unix.SYS_FCHOWNAT,

		// Execution: not an allowlist (the agent runs arbitrary code by
		// definition). Exists to maintain the process table for attribution and
		// to let policy deny specific binaries as a guardrail.
		unix.SYS_EXECVE,
		unix.SYS_EXECVEAT,

		// Network: connect covers both outbound TCP (egress) and Unix socket
		// access (D-Bus, keyring, etc). socket/bind/listen are not intercepted
		// because creating or listening on a socket is harmless if connecting is
		// mediated.
		unix.SYS_CONNECT,
	}
}

// DeniedSyscalls returns syscalls that are always denied with ENOSYS.
// io_uring_setup is denied because seccomp cannot see operations submitted
// through io_uring. If a tool adopted io_uring for file access, policy would
// silently stop applying. Denying setup makes libraries fall back to ordinary
// syscalls. This protects observability, not the security boundary.
func DeniedSyscalls() []uint32 {
	return []uint32{
		unix.SYS_IO_URING_SETUP,
	}
}

const (
	auditArchX86_64 = 0xc000003e // AUDIT_ARCH_X86_64
	x32Bit          = 0x40000000 // __X32_SYSCALL_BIT
)

// SockFilter is a BPF instruction.
type SockFilter = unix.SockFilter

// BuildFilter constructs the BPF filter program.
//
// Structure:
//  1. Check arch == AUDIT_ARCH_X86_64. If not, ALLOW.
//  2. Check the x32 bit is not set. If set, ALLOW.
//  3. Load syscall number.
//  4. For each intercepted syscall: if match, USER_NOTIF.
//  5. For each denied syscall: if match, ERRNO(ENOSYS).
//  6. Default: ALLOW.
//
// Architecture check rationale: syscall numbers differ per ABI. On x86_64 a
// process can also enter through i386 or x32 ABIs where numbers differ (e.g.
// number 5 is open on i386 but fstat on x86_64). Without checking
// seccomp_data.arch, the filter would mis-identify syscalls. Non-x86_64 and
// x32 calls are allowed rather than killed because a legitimate 32-bit tool
// would die with no explanation. The gap (32-bit file access is invisible to
// policy) is accepted because nothing in Go/Java/Node workflows is 32-bit.
//
// Gravelpit is x86_64 only. arm64 would need its own syscall table.
func BuildFilter() []SockFilter {
	intercepted := InterceptedSyscalls()
	denied := DeniedSyscalls()

	var filter []SockFilter

	// Load arch: offsetof(seccomp_data, arch) = 4
	filter = append(filter, bpfStmt(bpfLD|bpfW|bpfABS, 4))

	// Check arch == AUDIT_ARCH_X86_64, if not jump to allow (last instruction).
	// Jump offset is calculated from the next instruction.
	// Remaining: load_nr(1) + x32_check(1) + intercepted(2*n) + denied(2*m) + allow(1)
	allowJump := uint8(1 + 1 + len(intercepted)*2 + len(denied)*2)
	filter = append(filter, bpfJump(bpfJMP|bpfJEQ|bpfK, auditArchX86_64, 0, allowJump))

	// Load syscall number: offsetof(seccomp_data, nr) = 0
	filter = append(filter, bpfStmt(bpfLD|bpfW|bpfABS, 0))

	// Check x32 bit. If set, jump to allow.
	// Remaining: intercepted(2*n) + denied(2*m) + allow(1) - 1 (for relative jump)
	x32Jump := uint8(len(intercepted)*2 + len(denied)*2)
	filter = append(filter, bpfJump(bpfJMP|bpfJSET|bpfK, x32Bit, x32Jump, 0))

	// For each intercepted syscall: compare, on match jump to next (ret), on miss skip.
	for _, nr := range intercepted {
		filter = append(filter, bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, 1))
		filter = append(filter, bpfStmt(bpfRET|bpfK, seccompRetUserNotif))
	}

	// For each denied syscall: compare, on match return ERRNO.
	for _, nr := range denied {
		filter = append(filter, bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, 1))
		filter = append(filter, bpfStmt(bpfRET|bpfK, seccompRetErrno|uint32(unix.ENOSYS)))
	}

	// Default: ALLOW.
	filter = append(filter, bpfStmt(bpfRET|bpfK, seccompRetAllow))

	return filter
}

// BPF instruction encoding constants.
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJSET = 0x40
	bpfK    = 0x00
	bpfRET  = 0x06

	seccompRetAllow     = 0x7fff0000
	seccompRetUserNotif = 0x7fc00000
	seccompRetErrno     = 0x00050000
)

func bpfStmt(code uint16, k uint32) SockFilter {
	return SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) SockFilter {
	return SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
