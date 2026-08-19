// child.go implements the re-executed child that installs the seccomp filter
// and execs the target command.
//
// How the sandbox starts:
//
//	gravelpit run -- <cmd>   (parent, the supervisor)
//	  |
//	  |  re-executes itself with envSandboxChild=1 and one socket on fd 3
//	  v
//	gravelpit (child)  -> RunSandboxChild()
//	  |  installs seccomp filter, sends the notify fd to the parent, execs <cmd>
//	  v
//	<cmd>              (the sandboxed target, now filtered)
//
// The child re-executes into a fresh, fully-started Go runtime, so this code
// can allocate and use normal Go APIs. That is the reason for the re-exec:
// the seccomp setup needs a working runtime, which a raw fork() child does not
// have.
package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/seccomp"
)

// EnvSandboxChild marks a re-executed process as the sandbox child. The parent
// sets it before re-exec; the child checks it via IsSandboxChild.
const EnvSandboxChild = "GRAVELPIT_SANDBOX_CHILD"

// childSocketFd is the fd of the socket to the parent, inherited via
// exec.Cmd.ExtraFiles (fd 3 is the first extra file after stdio).
const childSocketFd = 3

// seccomp(2) flags, see linux/seccomp.h.
const (
	// seccompFilterFlagNewListener makes seccomp(2) return a user-notification fd.
	seccompFilterFlagNewListener = 0x08
	// seccompFilterFlagWaitKillableRecv (Linux 5.19) lets the target receive
	// non-fatal signals while waiting for the supervisor's response. Without it,
	// a wedged supervisor produces an agent that cannot be interrupted from the
	// keyboard (Ctrl+C is SIGINT, a non-fatal signal).
	seccompFilterFlagWaitKillableRecv = 0x20
)

// prSetNoNewPrivs is the prctl option to disable privilege escalation.
const prSetNoNewPrivs = 38

// IsSandboxChild reports whether this process is the re-executed sandbox child.
// The parent sets envSandboxChild before re-exec.
func IsSandboxChild() bool {
	return os.Getenv(EnvSandboxChild) == "1"
}

// RunSandboxChild installs the seccomp filter, hands the notification fd to the
// parent over childSocketFd, then execs the target command. It never returns:
// it either execs the target or exits the process on error.
//
// os.Args[0] is this gravelpit binary; os.Args[1:] is the target command and
// its arguments.
func RunSandboxChild() {
	// Lock to a single OS thread: seccomp(2) without TSYNC applies only to the
	// calling thread, and the filter must be in place on the thread that execs.
	runtime.LockOSThread()

	// os.Args[0] is this gravelpit binary (the re-executed self). The target
	// command and its arguments are the rest.
	target := os.Args[1:]
	if len(target) == 0 || target[0] == "" {
		fatal("missing target command")
	}

	// Disable privilege escalation, required before installing a seccomp filter
	// as an unprivileged process.
	if err := prctl(prSetNoNewPrivs, 1, 0, 0, 0); err != nil {
		fatal("PR_SET_NO_NEW_PRIVS: %v", err)
	}

	// Install the filter and get back a user-notification fd.
	notifFd, err := installFilter()
	if err != nil {
		fatal("installing seccomp filter: %v", err)
	}

	// Send the notify fd to the parent (the supervisor) and wait for its ack.
	if err := sendNotifyFd(notifFd); err != nil {
		fatal("sending notify fd to parent: %v", err)
	}

	// The child must not keep the notify fd or the parent socket open. Whoever
	// holds the notify fd is the supervisor for that filter and can answer its
	// own notifications with allow. Leaving it open hands the sandboxed process
	// complete control over its own policy.
	_ = unix.Close(notifFd)
	_ = unix.Close(childSocketFd)
	closeExtraFds()

	// Exec the target command. The seccomp filter survives execve. Drop the
	// sandbox-child marker so the target (and its children) do not inherit it.
	path, err := lookPath(target[0])
	if err != nil {
		fatal("%v", err)
	}
	if err := unix.Exec(path, target, childEnviron()); err != nil {
		fatal("exec %s: %v", path, err)
	}
}

// childEnviron returns the environment for the target with the sandbox-child
// marker removed, so the target does not think it is the sandbox child.
func childEnviron() []string {
	env := os.Environ()
	out := env[:0]
	prefix := EnvSandboxChild + "="
	for _, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			continue
		}
		out = append(out, e)
	}
	return out
}

// installFilter builds and installs the BPF filter with a new listener, and
// returns the user-notification fd.
//
// SECCOMP_FILTER_FLAG_NEW_LISTENER and SECCOMP_FILTER_FLAG_TSYNC are mutually
// exclusive. TSYNC is not needed because the filter is installed while this
// helper is single-threaded and is inherited by every thread and child process
// afterwards. The filter is immutable once installed and cannot be changed for
// the lifetime of the sandbox.
func installFilter() (int, error) {
	filterInsns := seccomp.BuildFilter()
	prog := unix.SockFprog{
		Len:    uint16(len(filterInsns)),
		Filter: &filterInsns[0],
	}
	flags := uintptr(seccompFilterFlagNewListener | seccompFilterFlagWaitKillableRecv)
	notifFd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flags,
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return -1, errno
	}
	return int(notifFd), nil
}

// sendNotifyFd sends notifFd to the parent over childSocketFd using SCM_RIGHTS,
// then waits for a one-byte ack so the parent has installed it before we exec.
//
// The ack is required: if the child closes the fd before the parent receives it,
// the fd is lost and every intercepted syscall returns ENOSYS.
func sendNotifyFd(notifFd int) error {
	rights := unix.UnixRights(notifFd)
	if err := unix.Sendmsg(childSocketFd, []byte{0}, rights, nil, 0); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := readFull(childSocketFd, ack); err != nil {
		return fmt.Errorf("waiting for ack: %w", err)
	}
	return nil
}

// fatal prints an error prefixed with the child name and exits.
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gravelpit sandbox child: "+format+"\n", args...)
	os.Exit(1)
}

// prctl wraps the prctl(2) syscall.
func prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// readFull reads exactly len(buf) bytes from fd, retrying on EINTR.
func readFull(fd int, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := unix.Read(fd, buf[total:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("unexpected EOF")
		}
		total += n
	}
	return total, nil
}

// closeExtraFds closes all open file descriptors above 2, reading /proc/self/fd
// to enumerate them. This keeps the target from inheriting stray fds.
func closeExtraFds() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		for fd := 3; fd < 1024; fd++ {
			_ = unix.Close(fd)
		}
		return
	}
	for _, e := range entries {
		var fd int
		if _, err := fmt.Sscan(e.Name(), &fd); err != nil {
			continue
		}
		if fd <= 2 {
			continue
		}
		_ = unix.Close(fd)
	}
}

// lookPath returns the full path for a command, searching PATH if necessary.
func lookPath(name string) (string, error) {
	if len(name) > 0 && name[0] == '/' {
		return name, nil
	}
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/local/bin:/usr/bin:/bin"
	}
	for start := 0; start <= len(pathEnv); {
		end := start
		for end < len(pathEnv) && pathEnv[end] != ':' {
			end++
		}
		dir := pathEnv[start:end]
		if dir == "" {
			dir = "."
		}
		full := dir + "/" + name
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
		start = end + 1
	}
	return "", fmt.Errorf("command not found: %s", name)
}
