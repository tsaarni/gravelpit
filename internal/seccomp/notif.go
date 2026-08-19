// notif.go provides low-level ioctl wrappers for seccomp user notification send/recv.
package seccomp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// SeccompData matches the kernel's seccomp_data structure.
type SeccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// SeccompNotif matches the kernel's seccomp_notif structure.
type SeccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  SeccompData
}

// SeccompNotifResp matches the kernel's seccomp_notif_resp structure.
type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// SECCOMP_USER_NOTIF_FLAG_CONTINUE tells the kernel to continue the syscall.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE = 0x00000001

// NotifRecv receives a notification from the seccomp notif fd.
func NotifRecv(fd int) (*SeccompNotif, error) {
	req := &SeccompNotif{}
	err := ioctlNotifRecv(fd, req)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// NotifSend sends a response to a seccomp notification.
func NotifSend(fd int, resp *SeccompNotifResp) error {
	return ioctlNotifSend(fd, resp)
}

// NotifIDValid checks that the notification with the given id is still valid
// (the target process has not died or had its syscall interrupted).
// Returns nil if valid, non-nil otherwise.
func NotifIDValid(fd int, id uint64) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_ID_VALID),
		uintptr(unsafe.Pointer(&id)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlNotifRecv(fd int, req *SeccompNotif) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV),
		uintptr(unsafe.Pointer(req)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlNotifSend(fd int, resp *SeccompNotifResp) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND),
		uintptr(unsafe.Pointer(resp)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
