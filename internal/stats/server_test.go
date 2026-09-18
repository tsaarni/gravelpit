// server_test.go tests the RPC server's socket file lifecycle.
package stats

import (
	"os"
	"testing"
)

// Close must remove the socket file. This is the cleanup runSandbox relies on
// via defer to avoid leaking gravelpit-*.sock files in XDG_RUNTIME_DIR on every
// sandbox session exit.
func TestServerCloseRemovesSocketFile(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	srv, err := NewServer(NewCollector(), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sockPath := srv.SockPath()
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket file missing after NewServer: %v", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file still exists after Close: err = %v", err)
	}
}
