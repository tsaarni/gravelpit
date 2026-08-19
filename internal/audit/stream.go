// Streamer fans audit records out to subscribed clients over per-client channels.
package audit

import (
	"sync"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

// Streamer multiplexes AuditRecords to a set of subscriber channels.
// Each subscriber receives a non-blocking send; slow readers miss records
// rather than blocking the writer.
type Streamer struct {
	mu          sync.Mutex
	subscribers map[chan *schema.AuditRecord]struct{}
}

// NewStreamer returns an empty Streamer.
func NewStreamer() *Streamer {
	return &Streamer{
		subscribers: make(map[chan *schema.AuditRecord]struct{}),
	}
}

// Subscribe returns a new channel that will receive published records.
// The channel is buffered (16 slots) so a momentarily slow reader does not
// miss every event immediately.
func (s *Streamer) Subscribe() chan *schema.AuditRecord {
	ch := make(chan *schema.AuditRecord, 16)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber set and closes it.
func (s *Streamer) Unsubscribe(ch chan *schema.AuditRecord) {
	s.mu.Lock()
	delete(s.subscribers, ch)
	s.mu.Unlock()
	close(ch)
}

// Publish sends r to every subscriber. The send is non-blocking; a full
// subscriber channel causes the record to be dropped for that subscriber.
func (s *Streamer) Publish(r *schema.AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for ch := range s.subscribers {
		select {
		case ch <- r:
		default:
			// Subscriber is not keeping up; drop this record for them.
		}
	}
}
