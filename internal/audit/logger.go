// Package audit provides async JSON-lines audit logging.
//
// Design:
//   - All decisions are recorded by default (not only denials) so that actions
//     can be tightened later based on what actually happened. Only recording
//     denials throws away the working set.
//   - Writes go through a bounded channel so auditing never blocks a verdict.
//     On overflow, events are dropped and a counter is recorded.
//   - The file is opened with O_APPEND so concurrent sessions can share it.
//   - Known-benign noise is suppressed with audit:false on a rule rather than
//     being filtered downstream.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

const queueSize = 4096

// Logger writes audit records as JSON lines to a file asynchronously.
// Writes go through a bounded channel; on overflow records are dropped and
// counted.
type Logger struct {
	queue   chan *schema.AuditRecord
	file    *os.File
	path    string
	level   string // "all" or "denials"
	dropped int64  // accessed atomically
	done    chan struct{}
	wg      sync.WaitGroup
}

// New creates a Logger that writes to path.
// level must be "all" or "denials".
func New(path string, level string) (*Logger, error) {
	if level != "all" && level != "denials" {
		return nil, fmt.Errorf("audit: invalid level %q, must be \"all\" or \"denials\"", level)
	}

	f, err := openAppend(path)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}

	l := &Logger{
		queue: make(chan *schema.AuditRecord, queueSize),
		file:  f,
		path:  path,
		level: level,
		done:  make(chan struct{}),
	}

	l.wg.Add(1)
	go l.run()

	return l, nil
}

// Log enqueues a record for writing. It is non-blocking; if the queue is full
// the record is dropped and the dropped counter is incremented.
// When level is "denials", only deny verdicts are logged.
func (l *Logger) Log(r *schema.AuditRecord) {
	if l.level == "denials" && r.Verdict != schema.VerdictDeny {
		return
	}
	select {
	case l.queue <- r:
	default:
		atomic.AddInt64(&l.dropped, 1)
	}
}

// Close flushes all queued records and closes the log file.
func (l *Logger) Close() error {
	close(l.done)
	l.wg.Wait()
	return l.file.Close()
}

// run is the single writer goroutine. It drains the queue and writes JSON lines.
func (l *Logger) run() {
	defer l.wg.Done()

	for {
		select {
		case r := <-l.queue:
			l.write(r)

		case <-l.done:
			// Drain remaining records before exiting.
			for {
				select {
				case r := <-l.queue:
					l.write(r)
				default:
					return
				}
			}
		}
	}
}

// write serialises r to a JSON line. If dropped events have accumulated since
// the last write, it emits a synthetic record first.
func (l *Logger) write(r *schema.AuditRecord) {
	n := atomic.SwapInt64(&l.dropped, 0)
	if n > 0 {
		drop := &schema.AuditRecord{
			Timestamp: time.Now().UTC(),
			Event:     schema.Event{Action: schema.Action("audit_overflow")},
			Message:   fmt.Sprintf("%d audit records dropped due to queue overflow", n),
		}
		l.writeLine(drop)
	}

	l.writeLine(r)
}

// writeLine marshals r to JSON and appends it to the file.
func (l *Logger) writeLine(r *schema.AuditRecord) {
	data, err := json.Marshal(r)
	if err != nil {
		slog.Error("audit marshal error", "error", err)
		return
	}
	data = append(data, '\n')

	if _, err := l.file.Write(data); err != nil {
		slog.Error("audit write error", "error", err)
	}
}

// openAppend opens path for appending (O_APPEND | O_CREATE | O_WRONLY),
// creating parent directories as needed.
func openAppend(path string) (*os.File, error) {
	dir := dirOf(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// dirOf returns the directory part of a file path.
func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}
