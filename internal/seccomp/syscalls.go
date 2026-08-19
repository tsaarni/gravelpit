// syscalls.go maps intercepted syscall numbers to names and back.
package seccomp

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

// syscallNames covers every syscall InterceptedSyscalls returns. Package level,
// not built per call: the lookup runs for every intercepted syscall on the
// notification path.
//
// Numbers are architecture specific, which is why this maps the numbers the
// filter uses rather than a portable name list.
var syscallNames = map[int]string{
	int(unix.SYS_OPEN):      "open",
	int(unix.SYS_OPENAT):    "openat",
	int(unix.SYS_OPENAT2):   "openat2",
	int(unix.SYS_UNLINK):    "unlink",
	int(unix.SYS_UNLINKAT):  "unlinkat",
	int(unix.SYS_RMDIR):     "rmdir",
	int(unix.SYS_RENAME):    "rename",
	int(unix.SYS_RENAMEAT):  "renameat",
	int(unix.SYS_RENAMEAT2): "renameat2",
	int(unix.SYS_TRUNCATE):  "truncate",
	int(unix.SYS_MKDIR):     "mkdir",
	int(unix.SYS_MKDIRAT):   "mkdirat",
	int(unix.SYS_CHMOD):     "chmod",
	int(unix.SYS_FCHMODAT):  "fchmodat",
	int(unix.SYS_CHOWN):     "chown",
	int(unix.SYS_FCHOWNAT):  "fchownat",
	int(unix.SYS_EXECVE):    "execve",
	int(unix.SYS_EXECVEAT):  "execveat",
	int(unix.SYS_CONNECT):   "connect",
}

// syscallNumbers is the reverse of syscallNames, built once.
var syscallNumbers = buildSyscallNumbers()

func buildSyscallNumbers() map[string]int {
	m := make(map[string]int, len(syscallNames))
	for nr, name := range syscallNames {
		m[name] = nr
	}
	return m
}

// SyscallName returns the name for a syscall number. A number the filter does
// not intercept renders as syscall_<nr> rather than an error, because the name
// is only used for reporting and an unexpected number is still worth printing.
func SyscallName(nr int) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// SyscallNumber returns the number for an intercepted syscall name.
func SyscallNumber(name string) (int, bool) {
	nr, ok := syscallNumbers[name]
	return nr, ok
}

// SyscallNames returns the intercepted syscall names, sorted, for telling the
// user which names are accepted.
func SyscallNames() []string {
	names := make([]string, 0, len(syscallNames))
	for _, name := range syscallNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
