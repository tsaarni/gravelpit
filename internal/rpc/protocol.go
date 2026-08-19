// Package rpc defines the request/response protocol between the sandbox child and the supervisor.
package rpc

import "time"

// Environment variable that holds the path to the supervisor RPC socket.
const EnvSockPath = "GRAVELPIT_SUPERVISOR_SOCK"

// Command names sent by the client.
const (
	CmdSummary = "summary"
	CmdRecent  = "recent"
	CmdDenies  = "denies"
	CmdReload  = "reload"
)

// Request is sent from the client to the supervisor.
type Request struct {
	Command string `json:"command"`
}

// Names of the in-memory tables reported in SummaryResponse.Caches.
const (
	CacheDecisions = "decisions"
	CacheProcesses = "processes"
)

// CacheStats describes one in-memory table. Bytes is an estimate, see the Stats
// methods on policy.Cache and process.Table.
type CacheStats struct {
	Name        string `json:"name"`
	Entries     int    `json:"entries"`
	Capacity    int    `json:"capacity"`
	Bytes       int    `json:"bytes"`
	Hits        int64  `json:"hits"`
	Misses      int64  `json:"misses"`
	HitsTracked bool   `json:"hits_tracked"` // false when the table has no hit counters
}

// SummaryResponse is returned by the summary command.
type SummaryResponse struct {
	Uptime        string           `json:"uptime"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	TotalRequests int64            `json:"total_requests"`
	TotalAllows   int64            `json:"total_allows"`
	TotalDenies   int64            `json:"total_denies"`
	ReloadCount   int64            `json:"reload_count"`
	ActionAllows  map[string]int64 `json:"action_allows"`
	ActionDenies  map[string]int64 `json:"action_denies"`
	Caches        []CacheStats     `json:"caches"`
}

// Cache returns the stats for a named table, or nil when the supervisor did not
// report it.
func (s *SummaryResponse) Cache(name string) *CacheStats {
	for i := range s.Caches {
		if s.Caches[i].Name == name {
			return &s.Caches[i]
		}
	}
	return nil
}

// AccessEntry records a single intercepted syscall with its verdict.
type AccessEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	Verdict   string    `json:"verdict"` // "allow" or "deny"
	Rule      string    `json:"rule,omitempty"`
}

// RecentResponse is returned by the recent command.
type RecentResponse struct {
	Entries []AccessEntry `json:"entries"`
}

// ReloadResponse is returned by the reload command.
type ReloadResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ErrorResponse is returned when the command is unknown.
type ErrorResponse struct {
	Error string `json:"error"`
}
