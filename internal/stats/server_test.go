// server_test.go tests the RPC server's socket file lifecycle.
package stats

import (
	"os"
	"path/filepath"
	"testing"
)

// Close must remove the socket file. This is the cleanup runSandbox relies on
// via defer to avoid leaking supervisor-*.sock files on every session exit.
func TestServerCloseRemovesSocketFile(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")

	srv, err := NewServer(sockPath, NewCollector(), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

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
