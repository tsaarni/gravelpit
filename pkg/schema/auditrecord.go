// auditrecord.go defines the JSON structure written to the audit log.
package schema

import "time"

// AuditRecord is the JSON structure written to the audit log. It embeds the
// Event (what happened) and adds the policy decision (what was decided).
type AuditRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Event
	Verdict Verdict  `json:"verdict"`
	Errno   string   `json:"errno,omitempty"`
	Rule    *RuleRef `json:"rule,omitempty"`
	Message string   `json:"message,omitempty"`
	// MessageDelivered is always emitted, including when false. With notify:false
	// a denial that tells the process nothing is a deliberate configuration, so
	// "not delivered" must be visible rather than an absent field.
	MessageDelivered bool  `json:"message_delivered"`
	LatencyUs        int64 `json:"latency_us"`
	CacheHit         bool  `json:"cache_hit,omitempty"`
	// Unresolved holds the reason a path argument could not be turned into an
	// absolute path. When set, the denial came from the decoder, not from a
	// policy rule, and no rule was consulted.
	Unresolved string `json:"unresolved,omitempty"`
}

// RuleRef identifies which rule decided the verdict.
type RuleRef struct {
	Name string `json:"name"`
	File string `json:"file,omitempty"`
}
