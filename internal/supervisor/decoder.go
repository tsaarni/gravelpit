// decoder.go extracts syscall arguments from the target process memory and maps
// each intercepted syscall to a policy action.
package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/seccomp"
)

// DecodedEvent is the result of decoding a seccomp notification.
type DecodedEvent struct {
	Action     policy.Action
	Path       string // Primary path, absolute but not yet canonical
	SecondPath string // For rename*: destination path

	// For connect:
	Socket string // AF_UNIX socket path (or @name for abstract)
	Host   string // AF_INET/AF_INET6 address string
	Port   int    // AF_INET/AF_INET6 port
	Family string // "AF_INET", "AF_INET6", "AF_UNIX", or "AF_<n>"

	// Unresolved is set when a path argument could not be made absolute. Path
	// and SecondPath are left empty in that case so a relative path can never
	// reach policy matching, where it would match nothing and produce a deny
	// indistinguishable from a real policy decision.
	Unresolved       bool
	UnresolvedRaw    string // path as the process passed it, for diagnostics
	UnresolvedReason string

	// EmptyPath is set when the path argument was an empty string. The syscall
	// names no file and the kernel rejects it with ENOENT, so it is answered
	// with that errno rather than reported as a policy denial. Unresolved is
	// set too, so ignoring this field still fails closed.
	EmptyPath bool
}

// markUnresolved records the first resolution failure seen for an event.
func (e *DecodedEvent) markUnresolved(raw string, err error) {
	if e.Unresolved {
		return
	}
	e.Unresolved = true
	e.UnresolvedRaw = raw
	e.UnresolvedReason = err.Error()
}

// Decoder holds context needed to safely inspect a target process.
//
// Memory reads and /proc reads are bracketed by SECCOMP_IOCTL_NOTIF_ID_VALID
// to detect target death or syscall interruption. Without the check, a
// notification whose target already exited could be answered using /proc data
// belonging to an unrelated process that reused the pid.
//
// The second ID_VALID check (after reading bytes) is easy to miss. The target's
// blocked syscall can be interrupted by a signal handler at any moment; if it
// is, the process resumes and the buffer holding the path string can be reused
// for something else. Bytes read without a following check may be from an
// unrelated part of the target's memory.
type Decoder struct {
	notifFd int
	id      uint64
	pid     uint32
}

// NewDecoder creates a Decoder for the given notification.
func NewDecoder(notifFd int, req *seccomp.SeccompNotif) *Decoder {
	return &Decoder{
		notifFd: notifFd,
		id:      req.ID,
		pid:     req.Pid,
	}
}

// CheckValid returns nil if the notification is still live.
func (d *Decoder) CheckValid() error {
	return seccomp.NotifIDValid(d.notifFd, d.id)
}

// ReadString reads a NUL-terminated string from the target process's memory,
// bracketed by ID_VALID to detect stale notifications.
func (d *Decoder) ReadString(addr uintptr) string {
	if addr == 0 {
		return ""
	}
	if err := d.CheckValid(); err != nil {
		return ""
	}
	buf := make([]byte, unix.PathMax)
	localIov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	remoteIov := unix.RemoteIovec{Base: addr, Len: len(buf)}
	n, err := unix.ProcessVMReadv(int(d.pid),
		[]unix.Iovec{localIov},
		[]unix.RemoteIovec{remoteIov},
		0,
	)
	if err != nil || n == 0 {
		return ""
	}
	if err := d.CheckValid(); err != nil {
		return ""
	}
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

// ReadBytes reads exactly size bytes from the target process's memory at addr,
// bracketed by ID_VALID. Returns nil on error.
func (d *Decoder) ReadBytes(addr uintptr, size int) []byte {
	if addr == 0 || size == 0 {
		return nil
	}
	if err := d.CheckValid(); err != nil {
		return nil
	}
	buf := make([]byte, size)
	localIov := unix.Iovec{Base: &buf[0], Len: uint64(size)}
	remoteIov := unix.RemoteIovec{Base: addr, Len: size}
	n, err := unix.ProcessVMReadv(int(d.pid),
		[]unix.Iovec{localIov},
		[]unix.RemoteIovec{remoteIov},
		0,
	)
	if err != nil || n != size {
		return nil
	}
	if err := d.CheckValid(); err != nil {
		return nil
	}
	return buf
}

// Decode extracts the action and path from a seccomp notification by reading
// the target process's memory.
func Decode(notifFd int, req *seccomp.SeccompNotif) DecodedEvent {
	d := NewDecoder(notifFd, req)
	return d.Decode(req)
}

// Decode extracts the action and other fields from a seccomp notification.
func (d *Decoder) Decode(req *seccomp.SeccompNotif) DecodedEvent {
	nr := int(req.Data.Nr)

	switch nr {
	case int(unix.SYS_OPEN):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: openAction(flagsArg(req.Data.Args[1]))}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_OPENAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: openAction(flagsArg(req.Data.Args[2]))}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_OPENAT2):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		// Args[2] points to struct open_how { __u64 flags; __u64 mode; __u64 resolve; }
		// Read the first 8 bytes to get flags. Unlike the register arguments
		// these are already 64-bit fields, so no truncation applies.
		flags := 0
		if b := d.ReadBytes(uintptr(req.Data.Args[2]), 8); b != nil {
			flags = int(binary.LittleEndian.Uint64(b))
		}
		ev := DecodedEvent{Action: openAction(flags)}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_UNLINK), int(unix.SYS_RMDIR):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionDelete}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_UNLINKAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: policy.ActionDelete}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_MKDIR):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionWrite}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_MKDIRAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: policy.ActionWrite}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_RENAME):
		src := d.ReadString(uintptr(req.Data.Args[0]))
		dst := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: policy.ActionDelete}
		ev.Path = d.resolveCwd(&ev, src)
		ev.SecondPath = d.resolveCwd(&ev, dst)
		return ev

	case int(unix.SYS_RENAMEAT), int(unix.SYS_RENAMEAT2):
		src := d.ReadString(uintptr(req.Data.Args[1]))
		dst := d.ReadString(uintptr(req.Data.Args[3]))
		ev := DecodedEvent{Action: policy.ActionDelete}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), src)
		ev.SecondPath = d.resolveAt(&ev, dirfdArg(req.Data.Args[2]), dst)
		return ev

	case int(unix.SYS_TRUNCATE):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionDelete}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_CHMOD):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionMetadata}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_FCHMODAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: policy.ActionMetadata}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_CHOWN):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionMetadata}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_FCHOWNAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		ev := DecodedEvent{Action: policy.ActionMetadata}
		ev.Path = d.resolveAt(&ev, dirfdArg(req.Data.Args[0]), path)
		return ev

	case int(unix.SYS_EXECVE):
		path := d.ReadString(uintptr(req.Data.Args[0]))
		ev := DecodedEvent{Action: policy.ActionExec}
		ev.Path = d.resolveCwd(&ev, path)
		return ev

	case int(unix.SYS_EXECVEAT):
		path := d.ReadString(uintptr(req.Data.Args[1]))
		dirfd := dirfdArg(req.Data.Args[0])
		ev := DecodedEvent{Action: policy.ActionExec}
		const atEmptyPath = 0x1000
		if path == "" && flagsArg(req.Data.Args[4])&atEmptyPath != 0 {
			// execveat(fd, "", ..., AT_EMPTY_PATH) executes the fd itself, so
			// the fd is the target rather than a directory to resolve against.
			target, err := ResolveFdPath(d.pid, dirfd)
			if err != nil {
				ev.markUnresolved("", err)
				return ev
			}
			ev.Path = target
			return ev
		}
		ev.Path = d.resolveAt(&ev, dirfd, path)
		return ev

	case int(unix.SYS_CONNECT):
		ev := DecodedEvent{Action: policy.ActionConnect}
		addrPtr := uintptr(req.Data.Args[1])
		addrLen := int(req.Data.Args[2])
		if addrPtr != 0 && addrLen >= 2 {
			ev = d.parseSockaddr(addrPtr, addrLen)
		}
		return ev

	default:
		return DecodedEvent{Action: policy.ActionRead}
	}
}

// parseSockaddr reads and parses a sockaddr struct from the target's memory.
func (d *Decoder) parseSockaddr(addrPtr uintptr, addrLen int) DecodedEvent {
	ev := DecodedEvent{Action: policy.ActionConnect}

	// Cap addrLen to PATH_MAX to avoid huge allocations.
	if addrLen > unix.PathMax+2 {
		addrLen = unix.PathMax + 2
	}
	if addrLen < 2 {
		return ev
	}
	buf := d.ReadBytes(addrPtr, addrLen)
	if buf == nil {
		return ev
	}

	// sa_family is the first 2 bytes, native endian (little-endian on x86_64).
	family := binary.LittleEndian.Uint16(buf[0:2])

	switch family {
	case unix.AF_UNSPEC:
		ev.Family = "AF_UNSPEC"

	case unix.AF_INET:
		ev.Family = "AF_INET"
		if len(buf) >= 8 {
			port := binary.BigEndian.Uint16(buf[2:4])
			ip := net.IP(buf[4:8])
			ev.Host = ip.String()
			ev.Port = int(port)
		}

	case unix.AF_INET6:
		ev.Family = "AF_INET6"
		if len(buf) >= 28 {
			port := binary.BigEndian.Uint16(buf[2:4])
			// bytes 4-7 are flowinfo, skip them
			ip := net.IP(buf[8:24])
			ev.Host = ip.String()
			ev.Port = int(port)
		}

	case unix.AF_UNIX:
		ev.Family = "AF_UNIX"
		if addrLen <= 2 {
			// autobind: empty sun_path
			ev.Socket = ""
		} else {
			sunPath := buf[2:]
			// addrLen - 2 bytes available for sun_path
			n := addrLen - 2
			if n > len(sunPath) {
				n = len(sunPath)
			}
			sunPath = sunPath[:n]
			if len(sunPath) > 0 && sunPath[0] == 0 {
				// Abstract socket: replace leading NUL with '@'
				name := string(sunPath[1:])
				// Strip trailing NULs
				for i := len(name) - 1; i >= 0; i-- {
					if name[i] == 0 {
						name = name[:i]
					} else {
						break
					}
				}
				ev.Socket = "@" + name
			} else {
				// Filesystem socket: NUL-terminated
				end := 0
				for end < len(sunPath) && sunPath[end] != 0 {
					end++
				}
				ev.Socket = string(sunPath[:end])
			}
		}

	case unix.AF_NETLINK:
		ev.Family = "AF_NETLINK"

	default:
		ev.Family = fmt.Sprintf("AF_%d", family)
	}

	return ev
}

// openAction determines the policy action from open(2) flags.
func openAction(flags int) policy.Action {
	if flags&(unix.O_WRONLY|unix.O_RDWR|unix.O_APPEND|unix.O_CREAT|unix.O_TRUNC) != 0 {
		return policy.ActionWrite
	}
	return policy.ActionRead
}

// atFdcwd and the resolution helpers live in resolve.go.

// dirfdArg converts a raw syscall register value into a dirfd.
//
// A dirfd is an int, so only the low 32 bits are meaningful. The kernel copies
// the register as-is into seccomp_data.args, and userspace typically loads a
// negative constant with a 32-bit move, leaving the upper bits zero. AT_FDCWD
// (-100) therefore arrives as 0x00000000FFFFFF9C, not as a sign-extended
// 0xFFFFFFFFFFFFFF9C. Truncating to int32 first restores the sign.
//
// Without this every relative path fails the AT_FDCWD check, falls through to
// the dirfd lookup, and stays relative.
func dirfdArg(v uint64) int {
	return int(int32(v))
}

// flagsArg converts a raw syscall register value into a flags int. Flag
// arguments are also declared as int, so the same 32-bit truncation applies.
func flagsArg(v uint64) int {
	return int(int32(v))
}

// resolveAt makes a path argument absolute, recording failure on ev.
//
// The resolution reads /proc for the target, so it is bracketed by
// NOTIF_ID_VALID. Without the check a notification whose target already exited
// could be answered using /proc data belonging to an unrelated process that
// reused the pid.
func (d *Decoder) resolveAt(ev *DecodedEvent, dirfd int, path string) string {
	if err := d.CheckValid(); err != nil {
		ev.markUnresolved(path, fmt.Errorf("%w: notification no longer valid: %v", ErrUnresolved, err))
		return ""
	}

	resolved, err := ResolveSyscallPath(d.pid, dirfd, path)
	if err != nil {
		// Unresolved is set as well, so removing the EmptyPath handling in the
		// caller fails closed instead of matching an empty path against policy.
		if errors.Is(err, ErrEmptyPath) {
			ev.markUnresolved(path, err)
			ev.EmptyPath = true
			return ""
		}
		ev.markUnresolved(path, err)
		return ""
	}

	if err := d.CheckValid(); err != nil {
		ev.markUnresolved(path, fmt.Errorf("%w: notification no longer valid: %v", ErrUnresolved, err))
		return ""
	}
	return resolved
}

// resolveCwd makes a path argument absolute for syscalls without a dirfd, which
// interpret relative paths against the process cwd exactly as AT_FDCWD does.
func (d *Decoder) resolveCwd(ev *DecodedEvent, path string) string {
	return d.resolveAt(ev, atFdcwd, path)
}

// ReadString reads a NUL-terminated string from the target process's memory.
// This is the free-function form, kept for backward compatibility with tests.
func ReadString(pid uint32, addr uintptr) string {
	if addr == 0 {
		return ""
	}
	buf := make([]byte, unix.PathMax)
	localIov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	remoteIov := unix.RemoteIovec{Base: addr, Len: len(buf)}
	n, err := unix.ProcessVMReadv(int(pid),
		[]unix.Iovec{localIov},
		[]unix.RemoteIovec{remoteIov},
		0,
	)
	if err != nil || n == 0 {
		return ""
	}
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

// ReadCwd returns the current working directory of a process. The second result
// is false when it could not be read; callers must not substitute a default,
// because "/" would silently relocate every relative path to the filesystem root.
func ReadCwd(pid uint32) (string, bool) {
	target, err := readProcLink(pid, "cwd")
	if err != nil {
		return "", false
	}
	return target, true
}
