// message.go delivers denial messages to the target process's stderr.
package supervisor

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// DeliverMessage writes a denial message to the target process's stderr via
// /proc/<pid>/fd/2.
//
// This is best-effort by design:
//   - If stderr is a socket, the open fails with ENXIO and nothing is written.
//   - The write uses O_APPEND so it doesn't overwrite if stderr is a file.
//   - The write is non-blocking: if the pipe is full, the message is dropped
//     rather than blocking the supervisor.
//   - Control characters in the message are sanitised to prevent terminal escape
//     injection.
//
// The message lands on whichever process made the syscall, which may be a
// subprocess of the agent. The reliable channel for the human is the audit log.
func DeliverMessage(pid uint32, message string) error {
	path := fmt.Sprintf("/proc/%d/fd/2", pid)
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sanitized := sanitizeMessage(message)
	msg := fmt.Sprintf("[gravelpit] %s\n", sanitized)
	_, err = unix.Write(fd, []byte(msg))
	return err
}

// sanitizeMessage escapes control characters that could be used to inject
// terminal escape sequences. Newlines are preserved since messages are
// multi-line by design.
func sanitizeMessage(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
		} else if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, "\\x%02x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
