// client.go provides a helper for connecting to the supervisor RPC socket.
package rpc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Call connects to the supervisor socket, sends a request, and returns the raw JSON response.
func Call(req Request) ([]byte, error) {
	sockPath := os.Getenv(EnvSockPath)
	if sockPath == "" {
		return nil, fmt.Errorf("%s not set (run this from inside a sandbox)", EnvSockPath)
	}

	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to supervisor: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var buf [64 * 1024]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return buf[:n], nil
}
