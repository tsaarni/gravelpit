// event.go defines the syscall event passed to the policy engine for CEL evaluation.
//
// CEL environment binds these fields at the root of every evaluation. Functions
// return false for input that does not apply rather than raising an error.
// host is empty for a Unix socket connection and socket is empty for TCP, so a
// rule written for one kind of connection is still evaluated for the other.
// pathMatch("", glob) returns false rather than raising, because a runtime error
// means deny and that deny would apply to a connection an unrelated rule was
// about to allow.
//
// CEL's && and || absorb errors: false && error = false, true || error = true.
// A guard like `family == "AF_UNIX" && ...` protects the rest from inapplicable
// calls.
//
// $HOME, $XDG_*, $WORKDIR, $TMPDIR are expanded in every rule field at load
// time in one place. No field has different expansion rules from another.
package schema

// Action is the semantic operation derived from a syscall.
type Action string

const (
	ActionRead     Action = "read"
	ActionWrite    Action = "write"
	ActionDelete   Action = "delete"
	ActionMetadata Action = "metadata"
	ActionExec     Action = "exec"
	ActionConnect  Action = "connect"
)

// AllActions lists every valid action string.
var AllActions = []Action{
	ActionRead, ActionWrite, ActionDelete, ActionMetadata, ActionExec, ActionConnect,
}

// ParseAction returns the action for a string, or false if unknown.
func ParseAction(s string) (Action, bool) {
	switch Action(s) {
	case ActionRead, ActionWrite, ActionDelete, ActionMetadata, ActionExec, ActionConnect:
		return Action(s), true
	default:
		return "", false
	}
}

// Verdict is the outcome of policy evaluation.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Event is the decoded syscall event passed to the policy engine for CEL evaluation.
type Event struct {
	Path          string      `json:"path,omitempty" jsonschema:"description=Resolved absolute path of the file being accessed."`
	RequestedPath string      `json:"requested_path,omitempty" jsonschema:"description=Original path before symlink resolution. Equals path when no symlinks are involved."`
	Action        Action      `json:"action" jsonschema:"description=Semantic operation: read\\, write\\, delete\\, metadata\\, exec\\, or connect."`
	Syscall       SyscallInfo `json:"syscall" jsonschema:"description=Syscall that triggered this event."`
	Socket        string      `json:"socket,omitempty" jsonschema:"description=Path of the Unix domain socket for connect actions."`
	Host          string      `json:"host,omitempty" jsonschema:"description=Remote host for TCP connect actions."`
	Port          int         `json:"port,omitempty" jsonschema:"description=Remote port for TCP connect actions."`
	Family        string      `json:"family,omitempty" jsonschema:"description=Socket address family: AF_INET\\, AF_INET6\\, AF_UNIX\\, AF_NETLINK\\, or AF_UNSPEC."`
	Process       ProcessInfo `json:"process" jsonschema:"description=Information about the process making the syscall."`
	Sandbox       SandboxInfo `json:"sandbox" jsonschema:"description=Information about the sandbox the process runs in."`
	Ancestors     []string    `json:"ancestors,omitempty" jsonschema:"description=Exe basenames of ancestor processes\\, from immediate parent to oldest. Used via startedBy(name)."`
}

// SyscallInfo holds raw syscall data.
//
// Bound as the CEL "syscall" variable. Matching on it costs the decision cache
// for the targets the rule can match, because several syscalls share one action
// and the cache key holds only the action and the target.
type SyscallInfo struct {
	Name   string `json:"name" jsonschema:"description=Name of the syscall (e.g. openat\\, connect). Several syscalls map to one action\\, so this distinguishes them."`
	Number int    `json:"-" jsonschema:"description=Syscall number. Architecture specific; prefer syscall.name."`
}

// ProcessInfo holds data about the calling process.
type ProcessInfo struct {
	// PID is the id from the seccomp notification, which is a thread id. For a
	// threaded program it may not be the id ps shows; TGID is the process.
	PID  int    `json:"pid" jsonschema:"description=Thread ID from the seccomp notification. For a threaded program this is not the id ps shows; see tgid."`
	TGID int    `json:"tgid,omitempty" jsonschema:"description=Thread group id, the process ID as ps reports it. Recorded on denials."`
	PPID int    `json:"ppid,omitempty" jsonschema:"description=Parent process ID, from the process table."`
	Exe  string `json:"exe,omitempty" jsonschema:"description=Absolute path of the process executable."`
	Comm string `json:"comm,omitempty" jsonschema:"description=Short command name (first 15 bytes of the executable basename\\, as the kernel derives comm)."`
	// Cmdline has no writer yet. Reading it correctly means decoding the argv
	// pointer array from the execve arguments, because /proc/<pid>/cmdline at
	// execve notification time still holds the caller's argv.
	Cmdline []string `json:"cmdline,omitempty" jsonschema:"description=Full command-line arguments. NOT POPULATED YET: a rule matching on this never fires."`
	Cwd     string   `json:"cwd,omitempty" jsonschema:"description=Current working directory of the process. Read only when a rule needs process context\\, and on denials."`
}

// SandboxInfo identifies the sandbox.
type SandboxInfo struct {
	ID      string `json:"id,omitempty" jsonschema:"description=Unique sandbox identifier: the pid of the supervisor process."`
	Command string `json:"command,omitempty" jsonschema:"description=Top-level command that started the sandbox."`
	Workdir string `json:"workdir,omitempty" jsonschema:"description=Working directory of the sandbox root process. Same value $WORKDIR expands to."`
}
