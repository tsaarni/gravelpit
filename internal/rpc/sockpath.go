// sockpath.go provides helpers for the supervisor socket directory.
package rpc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// SockDir returns the directory holding supervisor sockets. Uses
// $XDG_RUNTIME_DIR/gravelpit when set, falls back to /tmp/gravelpit-<uid>.
func SockDir() string {
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "gravelpit")
	}
	return fmt.Sprintf("/tmp/gravelpit-%d", os.Getuid())
}

// NewSockPath returns a unique socket path in the supervisor directory.
func NewSockPath() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return filepath.Join(SockDir(), fmt.Sprintf("supervisor-%s.sock", hex.EncodeToString(b[:]))), nil
}

// EnsureSockDir creates the socket directory with mode 0700. The directory
// mode is what keeps other users out, not the socket's own mode (umask can
// weaken socket permissions on some kernels).
func EnsureSockDir() (string, error) {
	dir := SockDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating socket directory: %w", err)
	}
	// MkdirAll does not change mode of an existing directory.
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("setting socket directory mode: %w", err)
	}
	return dir, nil
}
