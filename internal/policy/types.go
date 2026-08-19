// Package policy implements CEL-based policy evaluation for gravelpit.
//
// Each intercepted syscall maps to exactly one action:
//
//	read     - open* without a write flag
//	write    - open* with O_WRONLY/O_RDWR/O_APPEND/O_CREAT/O_TRUNC, mkdir, mkdirat
//	delete   - unlink*, rmdir, rename* (checked for both source and dest), truncate
//	metadata - chmod, fchmodat, chown, fchownat
//	exec     - execve, execveat
//	connect  - connect (covers TCP egress and Unix socket access)
//
// rename* is checked twice: source (losing the file) and destination (being
// destroyed if it exists). A deny on either denies the syscall.
package policy

import "github.com/tsaarni/gravelpit/pkg/schema"

// Type aliases so that internal code and tests can continue using policy.X.
type Action = schema.Action

const (
	ActionRead     = schema.ActionRead
	ActionWrite    = schema.ActionWrite
	ActionDelete   = schema.ActionDelete
	ActionMetadata = schema.ActionMetadata
	ActionExec     = schema.ActionExec
	ActionConnect  = schema.ActionConnect
)

var AllActions = schema.AllActions

var ParseAction = schema.ParseAction

type Verdict = schema.Verdict

const (
	VerdictAllow = schema.VerdictAllow
	VerdictDeny  = schema.VerdictDeny
)

type Event = schema.Event
type SyscallInfo = schema.SyscallInfo
type ProcessInfo = schema.ProcessInfo
type SandboxInfo = schema.SandboxInfo
type Rule = schema.Rule

// Decision is the result of evaluating an event against the rule set.
type Decision struct {
	Verdict Verdict
	Rule    *Rule  // nil when decided by default deny
	Score   int    // Specificity score of the deciding match
	Message string // After placeholder interpolation
	Errno   string
}

// RuleMatch records a single rule's evaluation result, for diagnostics.
type RuleMatch struct {
	Rule    *Rule
	Matched bool
	Score   int
	Pattern string // The pattern that produced the score
	// Untested lists context variables the rule reads that the caller left
	// empty, such as "process.exe". Only set by Eval. A rule with this set did
	// not fail to apply, it could not be tested, and the two look identical in
	// the output otherwise.
	Untested []string
}
