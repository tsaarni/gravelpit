// server.go implements a Unix socket RPC server for querying stats and triggering reload.
package stats

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
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

// NewServer creates a server listening on the given Unix socket path.
func NewServer(sockPath string, collector *Collector, reload ReloadFunc) (*Server, error) {
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = ln.Close()
		return nil, err
	}

	return &Server{
		collector: collector,
		reload:    reload,
		listener:  ln,
		sockPath:  sockPath,
		done:      make(chan struct{}),
	}, nil
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
		encode(enc, s.collector.Summary())
	case rpc.CmdRecent:
		encode(enc, s.buildRecentResponse())
	case rpc.CmdDenies:
		encode(enc, s.buildDeniesResponse())
	case rpc.CmdReload:
		s.handleReload(enc)
	default:
		encode(enc, rpc.ErrorResponse{Error: "unknown command: " + req.Command})
	}
}

// encode writes a JSON response and logs any write error at debug level.
func encode(enc *json.Encoder, v any) {
	if err := enc.Encode(v); err != nil {
		slog.Debug("rpc server: encode error", "error", err)
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
		encode(enc, rpc.ReloadResponse{OK: false, Error: "reload not supported"})
		return
	}
	if err := s.reload(); err != nil {
		encode(enc, rpc.ReloadResponse{OK: false, Error: err.Error()})
		return
	}
	encode(enc, rpc.ReloadResponse{OK: true})
}
