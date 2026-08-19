// resolve.go turns syscall path arguments into absolute, canonical paths as the
// target process sees them.
//
// There is no cache. Any userspace cache would go stale when processes outside
// the sandbox change symlinks (other terminals, package managers, dotfile tools,
// or the agent's own daemonized children). This is for correctness, not
// hardening.
//
// Absolute paths mean the same thing to the supervisor and to the target because
// the sandbox shares the supervisor mount namespace and root. Adding namespaces
// later would break this assumption.
package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// atFdcwd is AT_FDCWD: the dirfd value meaning "relative to the cwd".
const atFdcwd = -100

// ErrUnresolved marks a path argument that could not be turned into an absolute
// path. Policy patterns are anchored to absolute paths, so a relative path would
// match no rule and produce a deny that looks like a policy decision instead of
// a resolution failure. Callers must fail closed and report the reason.
var ErrUnresolved = errors.New("path could not be resolved")

// ErrEmptyPath marks a path argument that was an empty string. This is not a
// decoding failure: the syscall names no file, and the kernel rejects it with
// ENOENT before touching the filesystem. There is nothing for policy to decide,
// so callers must not report it as a denial. It wraps ErrUnresolved so that a
// caller which does not special-case it still fails closed.
var ErrEmptyPath = errors.New("empty path argument")

// openat2Unavailable is set after openat2 reports ENOSYS, so old kernels take
// the lexical fallback without retrying the syscall on every notification.
var openat2Unavailable atomic.Bool

// ResolveSyscallPath makes a syscall path argument absolute using the target
// process view of the filesystem.
//
// This is the first of two resolution steps. It only makes the path absolute;
// it does not resolve symlinks. Symlink canonicalization is a separate step
// (CanonicalizePath) so that it can be skipped for actions that are allowed
// unconditionally, where no rule depends on the path.
//
// pid is the thread id from the notification. dirfd is the already
// sign-extended dirfd argument.
func ResolveSyscallPath(pid uint32, dirfd int, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: %w", ErrUnresolved, ErrEmptyPath)
	}
	if path[0] == '/' {
		return path, nil
	}

	base, err := targetBaseDir(pid, dirfd)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, path), nil
}

// targetBaseDir returns the directory that a relative path is interpreted
// against: the process cwd for AT_FDCWD, otherwise the directory the dirfd
// refers to.
func targetBaseDir(pid uint32, dirfd int) (string, error) {
	var link string
	if dirfd == atFdcwd {
		link = "cwd"
	} else {
		if dirfd < 0 {
			// A negative dirfd that is not AT_FDCWD is invalid. The kernel will
			// reject the syscall with EBADF, but decoding must not invent a path.
			return "", fmt.Errorf("%w: invalid dirfd %d", ErrUnresolved, dirfd)
		}
		link = "fd/" + strconv.Itoa(dirfd)
	}

	target, err := readProcLink(pid, link)
	if err != nil {
		return "", err
	}
	return target, nil
}

// readProcLink reads a /proc/<pid>/<name> symlink for the target process and
// validates that the result is usable as a filesystem path.
//
// Two /proc behaviours have to be handled:
//
//   - Not every fd is a filesystem path. Sockets, pipes and anonymous inodes
//     read back as "socket:[12345]", "pipe:[12345]", "anon_inode:..." or
//     "memfd:name". These have no leading "/" and must not be joined onto.
//   - When the target has been unlinked the kernel appends " (deleted)" to the
//     link. Joining onto that produces a path that does not exist but may still
//     match a policy pattern.
//
// A directory can also be legitimately named "... (deleted)", so the suffix
// alone is not proof of deletion. st_nlink == 0 is the reliable test, and is
// only consulted when the suffix is present.
func readProcLink(pid uint32, name string) (string, error) {
	procPath := fmt.Sprintf("/proc/%d/%s", pid, name)

	target, err := os.Readlink(procPath)
	if err != nil {
		// The notification carries a thread id. A thread can exit while the
		// rest of the process keeps running, which removes /proc/<tid> even
		// though the fd table is still alive under the thread group leader.
		// Retry there before giving up.
		if tgid, ok := readTgid(pid); ok && tgid != pid {
			procPath = fmt.Sprintf("/proc/%d/%s", tgid, name)
			target, err = os.Readlink(procPath)
		}
		if err != nil {
			return "", fmt.Errorf("%w: reading %s: %v", ErrUnresolved, procPath, err)
		}
	}

	if !strings.HasPrefix(target, "/") {
		return "", fmt.Errorf("%w: %s is not a filesystem path (%q)", ErrUnresolved, procPath, target)
	}

	if strings.HasSuffix(target, " (deleted)") {
		if deleted, known := linkTargetDeleted(procPath); known && deleted {
			return "", fmt.Errorf("%w: %s refers to a deleted path", ErrUnresolved, procPath)
		}
	}

	return target, nil
}

// linkTargetDeleted reports whether a /proc link points at an unlinked object.
// The second result is false when this could not be determined.
func linkTargetDeleted(procPath string) (deleted, known bool) {
	var st unix.Stat_t
	// O_PATH follows the /proc magic link without needing read permission on
	// the target and without any side effect on the target itself.
	fd, err := unix.Open(procPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, false
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Fstat(fd, &st); err != nil {
		return false, false
	}
	return st.Nlink == 0, true
}

// readTgid returns the thread group leader pid for a thread id.
func readTgid(tid uint32) (uint32, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Tgid:")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	}
	return 0, false
}

// ResolveFdPath returns the path an fd of the target process refers to. Used by
// execveat with AT_EMPTY_PATH, where the fd itself is the target rather than a
// directory to resolve a relative path against.
func ResolveFdPath(pid uint32, fd int) (string, error) {
	if fd < 0 {
		return "", fmt.Errorf("%w: invalid fd %d", ErrUnresolved, fd)
	}
	return readProcLink(pid, "fd/"+strconv.Itoa(fd))
}

// CanonicalizePathForPid canonicalizes an absolute path as the target process
// sees it. Use this instead of CanonicalizePath whenever the target pid is
// known.
//
// procfs needs its own handling. "/proc/self" and "/dev/fd" are magic links
// meaning "whoever is reading them". CanonicalizePath resolves symlinks by
// opening directories in the supervisor, so those links resolve to the
// supervisor instead of the target: a shell redirecting to /dev/fd/1 was
// evaluated as the supervisor's fd table, matched no rule, and was denied.
//
// References to the target's own process are rewritten to a stable
// "/proc/self/..." form so a rule can allow a process its own fds. Other pids
// are left literal, so allowing own fds does not allow every same-uid process's
// fds. Magic links are never followed here: the policy decides on the procfs
// path the process actually named, not on wherever the link happens to point in
// the supervisor's context.
func CanonicalizePathForPid(path string, pid uint32) string {
	if normalized, ok := normalizeProcPath(path, pid); ok {
		return normalized
	}
	return CanonicalizePath(path)
}

// normalizeProcPath rewrites procfs and /dev/fd paths. The second result is
// false when path is not one of those, meaning ordinary canonicalization
// applies.
func normalizeProcPath(path string, pid uint32) (string, bool) {
	if path == "" || path[0] != '/' {
		return "", false
	}
	cleaned := filepath.Clean(path)

	// /dev/fd is a symlink to /proc/self/fd, so it names the caller's own fds.
	if rest, ok := cutPrefixSegment(cleaned, "/dev/fd"); ok {
		return "/proc/self/fd" + rest, true
	}

	rest, ok := cutPrefixSegment(cleaned, "/proc")
	if !ok || rest == "" {
		return "", false
	}

	// rest is "/<subject>/..." where subject is self, thread-self or a pid.
	subject, tail := splitFirstSegment(rest[1:])
	switch subject {
	case "self":
		return "/proc/self/" + tail, true
	case "thread-self":
		// /proc/thread-self points at <tgid>/task/<tid>. Both name the caller,
		// so collapse to self rather than inventing a task path.
		return "/proc/self/" + tail, true
	}

	n, err := strconv.ParseUint(subject, 10, 32)
	if err != nil {
		// Not a pid: /proc/meminfo, /proc/sys/... Leave it alone, but do not
		// canonicalize, since /proc symlinks must not be followed here.
		return cleaned, true
	}
	if uint32(n) == pid {
		return "/proc/self/" + tail, true
	}
	// A thread id names the same process as its thread group leader.
	if tgid, ok := readTgid(pid); ok && uint32(n) == tgid {
		return "/proc/self/" + tail, true
	}
	// Another process. Keep it literal so policy can deny it independently.
	return cleaned, true
}

// cutPrefixSegment reports whether path is prefix or lies under it, returning
// the remainder including the leading "/". It avoids matching "/dev/fdinfo"
// for prefix "/dev/fd".
func cutPrefixSegment(path, prefix string) (string, bool) {
	if path == prefix {
		return "", true
	}
	if strings.HasPrefix(path, prefix+"/") {
		return path[len(prefix):], true
	}
	return "", false
}

// splitFirstSegment splits "a/b/c" into "a" and "b/c".
func splitFirstSegment(s string) (first, rest string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// CanonicalizePath resolves symlinks and ".." in the directory portion of an
// absolute path. The final component is left alone, because it may not exist
// yet (creation) and because for unlink and rename the link itself is the
// target rather than what it points to.
//
// The input must already be absolute. Absolute paths mean the same thing to the
// supervisor and to the target because the sandbox shares the supervisor mount
// namespace and root. Adding namespaces later would break that assumption and
// this would have to resolve against the target instead.
//
// A path whose directory does not exist is returned lexically cleaned. That is
// a normal case (mkdir, create in a new tree), not a resolution failure.
func CanonicalizePath(path string) string {
	if path == "" || path[0] != '/' {
		// Callers must resolve first. Returning the input unchanged keeps this
		// side effect free; the unresolved path is rejected before matching.
		return path
	}

	cleaned := filepath.Clean(path)

	final := filepath.Base(cleaned)
	if final == "/" || final == "." || final == ".." {
		// No distinct final component to preserve: the whole path names a
		// directory, so canonicalize all of it.
		if dir, ok := canonicalizeDir(cleaned); ok {
			return dir
		}
		return cleaned
	}

	dir, ok := canonicalizeDir(filepath.Dir(cleaned))
	if !ok {
		return cleaned
	}
	return filepath.Join(dir, final)
}

// canonicalizeDir returns the canonical path of an existing directory.
//
// The kernel performs the walk, so symlinks, ".." and mount points are
// interpreted exactly as they would be for the intercepted syscall. Resolving
// with string operations instead can disagree with the kernel, in particular
// for ".." crossing a symlink or a bind mount.
//
// When the directory does not exist the longest existing ancestor is
// canonicalized and the remaining components are appended. Without this a
// symlinked parent would stay unresolved whenever the leaf is missing, and
// policy would see a different path than the kernel acts on.
func canonicalizeDir(dir string) (string, bool) {
	var missing []string

	for {
		if resolved, ok := kernelResolveDir(dir); ok {
			if len(missing) == 0 {
				return resolved, true
			}
			// Append the components that do not exist yet, innermost last.
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached "/" without success.
			return "", false
		}
		missing = append(missing, filepath.Base(dir))
		dir = parent
	}
}

// kernelResolveDir opens a directory with O_PATH and reads back the path the
// kernel associates with it.
func kernelResolveDir(dir string) (string, bool) {
	fd, err := openPathDir(dir)
	if err != nil {
		return "", false
	}
	defer func() { _ = unix.Close(fd) }()

	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || !strings.HasPrefix(target, "/") {
		return "", false
	}
	// The directory was removed after being opened. Callers fall back to the
	// lexical path; treating it as resolved would strip the real name.
	if strings.HasSuffix(target, " (deleted)") {
		return "", false
	}
	return target, true
}

// openPathDir opens dir as an O_PATH directory fd.
//
// openat2 is preferred so RESOLVE_NO_MAGICLINKS can block the walk from passing
// through /proc magic links, which a sandboxed process could otherwise use to
// steer resolution. Kernels without openat2 fall back to plain open, which has
// no equivalent guard.
func openPathDir(dir string) (int, error) {
	if !openat2Unavailable.Load() {
		how := unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_MAGICLINKS,
		}
		fd, err := unix.Openat2(unix.AT_FDCWD, dir, &how)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOSYS) {
			return -1, err
		}
		openat2Unavailable.Store(true)
	}
	return unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}
