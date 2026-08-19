// server.go implements a Unix socket RPC server for querying stats and triggering reload.
package stats

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

// ReloadFunc is called when a reload command is received. It returns an error
// if the reload failed.
type ReloadFunc func() error

// Server listens on a Unix domain socket and responds to RPC requests.
type Server struct {
	collector *Collector
	reload    ReloadFunc
	listener  net.Listener
	sockPath  string
	wg        sync.WaitGroup
	done      chan struct{}
}

// NewServer creates a server with a unique socket path under XDG_RUNTIME_DIR.
func NewServer(collector *Collector, reload ReloadFunc) (*Server, error) {
	sockPath, err := uniqueSockPath()
	if err != nil {
		return nil, fmt.Errorf("generating socket path: %w", err)
	}

	os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	os.Chmod(sockPath, 0600)

	return &Server{
		collector: collector,
		reload:    reload,
		listener:  ln,
		sockPath:  sockPath,
		done:      make(chan struct{}),
	}, nil
}

// SockPath returns the socket path for passing to child processes.
func (s *Server) SockPath() string {
	return s.sockPath
}

// Serve accepts connections and handles requests. Blocks until Close is called.
func (s *Server) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				slog.Debug("rpc server accept error", "error", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

// Close stops the server and cleans up the socket file.
func (s *Server) Close() error {
	close(s.done)
	err := s.listener.Close()
	s.wg.Wait()
	os.Remove(s.sockPath)
	return err
}

// handleConn reads a single request and writes a JSON response.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	var req rpc.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		slog.Debug("rpc server: decode error", "error", err)
		return
	}

	enc := json.NewEncoder(conn)

	switch req.Command {
	case rpc.CmdSummary:
		enc.Encode(s.collector.Summary())
	case rpc.CmdRecent:
		enc.Encode(s.buildRecentResponse())
	case rpc.CmdDenies:
		enc.Encode(s.buildDeniesResponse())
	case rpc.CmdReload:
		s.handleReload(enc)
	default:
		enc.Encode(rpc.ErrorResponse{Error: "unknown command: " + req.Command})
	}
}

func (s *Server) buildRecentResponse() *rpc.RecentResponse {
	entries := s.collector.RecentAccesses(0)
	rpcEntries := make([]rpc.AccessEntry, len(entries))
	for i, e := range entries {
		rpcEntries[i] = rpc.AccessEntry{
			Timestamp: e.Timestamp,
			Action:    e.Action,
			Path:      e.Path,
			Verdict:   e.Verdict,
			Rule:      e.Rule,
		}
	}
	return &rpc.RecentResponse{Entries: rpcEntries}
}

func (s *Server) buildDeniesResponse() *rpc.RecentResponse {
	entries := s.collector.RecentDenies(0)
	rpcEntries := make([]rpc.AccessEntry, len(entries))
	for i, e := range entries {
		rpcEntries[i] = rpc.AccessEntry{
			Timestamp: e.Timestamp,
			Action:    e.Action,
			Path:      e.Path,
			Verdict:   e.Verdict,
			Rule:      e.Rule,
		}
	}
	return &rpc.RecentResponse{Entries: rpcEntries}
}

func (s *Server) handleReload(enc *json.Encoder) {
	if s.reload == nil {
		enc.Encode(rpc.ReloadResponse{OK: false, Error: "reload not supported"})
		return
	}
	if err := s.reload(); err != nil {
		enc.Encode(rpc.ReloadResponse{OK: false, Error: err.Error()})
		return
	}
	enc.Encode(rpc.ReloadResponse{OK: true})
}

// uniqueSockPath returns a socket path under XDG_RUNTIME_DIR (typically /run/user/<uid>/).
// Falls back to /tmp if XDG_RUNTIME_DIR is not set.
func uniqueSockPath() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("gravelpit-%s.sock", hex.EncodeToString(b[:]))
	return filepath.Join(dir, name), nil
}
