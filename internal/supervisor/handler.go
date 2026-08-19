// Package supervisor processes seccomp notifications against the policy engine.
//
// Concurrency contract: policy evaluation must be a pure function of the decoded
// event and the current rule set. No shared mutable state, no per-destination
// bookkeeping, no caching of verdicts across notifications (beyond the
// path-keyed cache). Identical events must never produce different verdicts.
// Every denial is written to the audit log before the response is sent, so a
// spurious denial is always visible.
//
// Error handling: every notification must produce a response, or the target
// blocks forever. RECV failing with EINTR or ENOENT means the target was killed
// or its syscall was interrupted, and is not fatal. CEL runtime errors cause
// deny with EACCES and are logged loudly.
package supervisor

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/process"
	"github.com/tsaarni/gravelpit/internal/seccomp"
	"github.com/tsaarni/gravelpit/internal/stats"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// Handler processes seccomp notifications against a policy engine.
type Handler struct {
	Engine *policy.Engine

	// EngineFunc, if set, is called on each notification to get the current
	// engine. This allows the daemon to swap the engine on policy reload
	// without restarting the handler. If nil, Engine is used directly.
	EngineFunc func() *policy.Engine

	// Cache holds recently evaluated policy decisions. A decision is cached
	// when no rule that reads process/ancestors/sandbox can match its target,
	// which is decided per action and per target rather than for the whole
	// policy. May be nil to disable.
	Cache *policy.Cache

	// OnDecision is called for every decision. Used for audit logging.
	// May be nil.
	OnDecision func(*schema.AuditRecord)

	// ProcessTable tracks processes by pid, built from execve notifications.
	// May be nil, in which case ancestor information is not populated.
	ProcessTable *process.Table

	// Stats collects runtime statistics for the status command. May be nil.
	Stats *stats.Collector

	// DefaultDenyMessage is delivered when a deny decision has no rule message.
	// If empty, no fallback message is sent.
	DefaultDenyMessage string

	// Sandbox identifies this sandbox. Bound as the CEL "sandbox" variable and
	// written to every audit record. Built once at startup; without it a rule
	// written against sandbox.workdir silently never matches.
	Sandbox schema.SandboxInfo
}

// engine returns the active policy engine.
func (h *Handler) engine() *policy.Engine {
	if h.EngineFunc != nil {
		return h.EngineFunc()
	}
	return h.Engine
}

// HandleSyscall processes a single intercepted syscall: decode args, evaluate
// policy, deliver denial message, respond allow or deny.
func (h *Handler) HandleSyscall(notifFd int, req *seccomp.SeccompNotif) {
	start := time.Now()

	ev := Decode(notifFd, req)

	// Fast path: if this action is unconditionally allowed, respond immediately
	// without resolving paths, reading /proc, or evaluating policy.
	eng := h.engine()
	isExec := ev.Action == policy.ActionExec
	if eng.IsUnconditionalAllow(ev.Action) {
		// The exec is allowed, so record it here: the slow path below is not
		// reached and ancestry must stay complete either way.
		if isExec && h.ProcessTable != nil {
			h.ProcessTable.RecordExec(int(req.Pid), ev.Path)
		}
		resp := &seccomp.SeccompNotifResp{ID: req.ID, Flags: seccomp.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		seccomp.NotifSend(notifFd, resp)
		if h.Stats != nil {
			path := ev.Path
			if path == "" {
				path = ev.Socket
			}
			h.Stats.RecordAllow(string(ev.Action), path, eng.UnconditionalAllowRule(ev.Action))
		}
		return
	}

	// An empty path argument names no file. The kernel rejects it with ENOENT
	// before touching the filesystem, so there is nothing for policy to decide.
	// Answer with that errno instead of a denial: reporting EACCES and
	// delivering a "location could not be determined" message describes a
	// decoding failure that did not happen, and fills the audit log with
	// denials for syscalls that were always going to fail.
	if ev.EmptyPath {
		resp := &seccomp.SeccompNotifResp{ID: req.ID, Error: -int32(unix.ENOENT)}
		seccomp.NotifSend(notifFd, resp)
		return
	}

	// A path that could not be made absolute must not be matched against
	// policy: patterns are anchored to absolute paths, so every rule would miss
	// and the result would be an implicit deny with no rule attached,
	// indistinguishable in the audit log from a real policy decision. Fail
	// closed with a reason instead.
	if ev.Unresolved {
		h.denyUnresolved(notifFd, req, &ev, start)
		return
	}

	// Resolve symlinks in the directory part of paths. Done after the
	// unconditional-allow check because it touches the filesystem. The target
	// pid is needed so that /proc/self and /dev/fd resolve to the target rather
	// than to the supervisor.
	//
	// The path before this step is kept: it is what the process named, and the
	// only way to see a symlink or /dev/fd rewrite in the audit log. It is also
	// what ${requestedPath} interpolates to.
	requestedPath := ev.Path
	ev.Path = CanonicalizePathForPid(ev.Path, req.Pid)
	if ev.SecondPath != "" {
		ev.SecondPath = CanonicalizePathForPid(ev.SecondPath, req.Pid)
	}

	// Cacheability is decided per action and per target, not for the policy as a
	// whole: a rule that reads process context only has to bypass the cache for
	// the targets it can actually match.
	target := cacheTarget(ev)
	useCache := h.Cache != nil && eng.CacheableTarget(ev.Action, target)
	useCache2 := ev.SecondPath != "" && h.Cache != nil && eng.CacheableTarget(ev.Action, ev.SecondPath)

	// Try cache early, before reading /proc for exe and ancestors.
	var decision policy.Decision
	cacheHit := false
	if useCache {
		earlyKey := policy.CacheKey{Action: ev.Action, Target: target}
		if cached, ok := h.Cache.Get(earlyKey); ok {
			decision = cached
			cacheHit = true
			if h.Stats != nil {
				h.Stats.RecordCacheHit()
			}
		}
	}

	// Also check the second path if this is a rename and the first path was cached.
	if cacheHit && ev.SecondPath != "" {
		key2 := policy.CacheKey{Action: ev.Action, Target: ev.SecondPath}
		cached2, ok := policy.Decision{}, false
		if useCache2 {
			cached2, ok = h.Cache.Get(key2)
		}
		if ok {
			if cached2.Verdict == policy.VerdictDeny {
				if decision.Verdict == policy.VerdictAllow ||
					(cached2.Rule != nil && decision.Rule == nil) {
					decision = cached2
				}
			}
		} else {
			// Second path not cached, or not cacheable: fall through to full
			// evaluation so the destination is decided against live context.
			cacheHit = false
		}
	}

	// Process identity, gathered at most once per notification and shared by
	// policy evaluation and the audit record. contextGathered records whether it
	// holds more than the pid.
	procInfo := schema.ProcessInfo{PID: int(req.Pid)}
	var ancestors []string
	contextGathered := false

	if !cacheHit {
		// Context is gathered only when a rule that can match one of these
		// targets reads it. The /proc reads and the ancestry walk are pure cost
		// for a policy where no rule does, which is the common case.
		if eng.NeedsProcessContext(ev.Action, target) ||
			(ev.SecondPath != "" && eng.NeedsProcessContext(ev.Action, ev.SecondPath)) {
			procInfo, ancestors = h.processContext(req.Pid)
			contextGathered = true
		}

		syscallName := seccomp.SyscallName(int(req.Data.Nr))

		pev := &schema.Event{
			Action:        ev.Action,
			Path:          ev.Path,
			RequestedPath: requestedPath,
			Socket:        ev.Socket,
			Host:          ev.Host,
			Port:          ev.Port,
			Family:        ev.Family,
			Syscall:       schema.SyscallInfo{Name: syscallName, Number: int(req.Data.Nr)},
			Process:       procInfo,
			Sandbox:       h.Sandbox,
			Ancestors:     ancestors,
		}

		decision = eng.Evaluate(pev)
		if useCache {
			key := policy.CacheKey{Action: ev.Action, Target: target}
			h.Cache.Put(key, decision)
			if h.Stats != nil {
				h.Stats.RecordCacheMiss()
			}
		}

		// For rename*, also evaluate the destination path. It carries the same
		// process context as the source: it is the same syscall by the same
		// process, and a rule reading process.exe must not see an empty value
		// for one half of a rename.
		if ev.SecondPath != "" {
			pev2 := &schema.Event{
				Action:    ev.Action,
				Path:      ev.SecondPath,
				Syscall:   schema.SyscallInfo{Name: syscallName, Number: int(req.Data.Nr)},
				Process:   procInfo,
				Sandbox:   h.Sandbox,
				Ancestors: ancestors,
			}
			d2 := eng.Evaluate(pev2)
			if useCache2 {
				key2 := policy.CacheKey{Action: ev.Action, Target: ev.SecondPath}
				h.Cache.Put(key2, d2)
			}
			if d2.Verdict == policy.VerdictDeny {
				if decision.Verdict == policy.VerdictAllow ||
					(d2.Rule != nil && decision.Rule == nil) {
					decision = d2
				}
			}
		}
	}

	// An allowed exec changes what the process is. Record it now that the verdict
	// is known: a denied exec never takes effect, and recording it would name a
	// binary the process never became. ev.Path is already canonicalized here.
	if isExec && decision.Verdict == policy.VerdictAllow && h.ProcessTable != nil {
		h.ProcessTable.RecordExec(int(req.Pid), ev.Path)
	}

	// Deliver denial message before responding (the process is still blocked).
	//
	// notify:false suppresses the rule message and the default fallback alike.
	// Without covering the fallback the option would be useless: an empty
	// message is exactly the case that falls through to DefaultDenyMessage,
	// which tells the reader to stop and ask the user, and is worse than the
	// rule's own text for a denial that is expected and handled.
	delivered := false
	if decision.Verdict == policy.VerdictDeny && decision.Rule.ShouldNotify() {
		msg := decision.Message
		if msg == "" {
			msg = h.DefaultDenyMessage
		}
		if msg != "" {
			DeliverMessage(req.Pid, msg)
			delivered = true
		}
	}

	// Log the decision.
	ruleName := ""
	if decision.Rule != nil {
		ruleName = decision.Rule.Name
	}
	logPath := ev.Path
	if logPath == "" && ev.Socket != "" {
		logPath = ev.Socket
	}
	if logPath == "" && ev.Host != "" {
		logPath = fmt.Sprintf("%s:%d", ev.Host, ev.Port)
	}

	// A rule with audit:false produces no record. Decided before the lookups
	// below so a suppressed record does not pay for reads only it needs.
	auditing := h.OnDecision != nil && decision.Rule.ShouldAudit()
	denied := decision.Verdict == policy.VerdictDeny

	// Fill in what the process table knows. This is a map lookup, so it costs
	// the same whether the record is written or not.
	if !contextGathered && h.ProcessTable != nil {
		if entry := h.ProcessTable.Lookup(int(req.Pid)); entry != nil {
			procInfo.Exe = entry.Exe
			procInfo.Comm = entry.Comm
			procInfo.PPID = entry.PPid
		}
	}
	if procInfo.Exe == "" && auditing {
		if exe := readExe(req.Pid); exe != "" {
			procInfo.Exe = exe
			// Keep what /proc just told us. The exec was never seen, but the
			// process is running now, so this is accurate, and the next syscall
			// from this pid is attributed from the table instead of another
			// /proc read. It also gives the record comm and ppid, which the
			// fallback alone cannot fill.
			if h.ProcessTable != nil {
				if entry := h.ProcessTable.RecordObserved(int(req.Pid), exe); entry != nil {
					procInfo.Comm = entry.Comm
					procInfo.PPID = entry.PPid
				}
			}
		}
	}

	// The rest is for the human reading the log afterwards, and each field costs
	// a /proc read. Denials are rare and are the records worth explaining, so
	// they are enriched and the allow path is left lean: with audit-level all,
	// paying this on every allowed read would dominate the log and the cost.
	if auditing && denied {
		if procInfo.Cwd == "" {
			if cwd, err := readProcLink(req.Pid, "cwd"); err == nil {
				procInfo.Cwd = cwd
			}
		}
		// The notification carries a thread id. /proc/<tid> disappears when the
		// thread exits, so for any Go binary the recorded pid may not be what ps
		// shows. Record the process id alongside it.
		if tgid, ok := readTgid(req.Pid); ok {
			procInfo.TGID = int(tgid)
		}
		// A top-level process legitimately has no ancestors inside the sandbox,
		// so this is keyed on whether the walk was done, not on the result.
		if !contextGathered && h.ProcessTable != nil {
			ancestors = h.ancestorNames(req.Pid)
		}
	}

	if denied {
		slog.Debug("deny", "action", ev.Action, "path", logPath, "rule", ruleName, "pid", req.Pid, "exe", procInfo.Exe)
	} else {
		slog.Debug("allow", "action", ev.Action, "path", logPath, "rule", ruleName, "pid", req.Pid)
	}

	latencyUs := time.Since(start).Microseconds()

	// Record stats if collector is configured.
	if h.Stats != nil {
		if denied {
			h.Stats.RecordDeny(string(ev.Action), logPath, ruleName)
		} else {
			h.Stats.RecordAllow(string(ev.Action), logPath, ruleName)
		}
	}

	// Build audit record. Stats above are recorded regardless of audit:false, so
	// 'gravelpit status' keeps a complete count even for suppressed rules.
	if auditing {
		errno := decision.Errno
		if denied {
			errno = recordErrno(ev.Action, decision.Errno)
		}
		rec := &schema.AuditRecord{
			Timestamp:        start.UTC(),
			Verdict:          decision.Verdict,
			Errno:            errno,
			Message:          decision.Message,
			MessageDelivered: delivered,
			LatencyUs:        latencyUs,
			CacheHit:         cacheHit,
		}
		rec.Event.Action = ev.Action
		rec.Event.Path = ev.Path
		// Only when it differs, or every record would carry the path twice.
		if requestedPath != ev.Path {
			rec.Event.RequestedPath = requestedPath
		}
		rec.Event.Socket = ev.Socket
		rec.Event.Host = ev.Host
		rec.Event.Port = ev.Port
		rec.Event.Family = ev.Family
		rec.Event.Process = procInfo
		rec.Event.Sandbox = h.Sandbox
		rec.Event.Ancestors = ancestors
		rec.Event.Syscall.Name = seccomp.SyscallName(int(req.Data.Nr))
		if decision.Rule != nil {
			rec.Rule = &schema.RuleRef{
				Name: decision.Rule.Name,
				File: decision.Rule.File,
			}
		}
		h.OnDecision(rec)
	}

	// Respond.
	resp := &seccomp.SeccompNotifResp{ID: req.ID}
	if decision.Verdict == policy.VerdictAllow {
		resp.Flags = seccomp.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else {
		resp.Error = -int32(denyErrno(ev.Action, decision.Errno))
	}
	seccomp.NotifSend(notifFd, resp)
}

// processContext gathers the identity a rule can match on. Called only when a
// rule that can match the target actually reads process context, so the /proc
// reads here are not on the common path.
//
// exe comes from /proc rather than the process table because it must be live:
// the table is only updated on execve, and a process that was never exec'd
// inside the sandbox has no entry.
func (h *Handler) processContext(pid uint32) (schema.ProcessInfo, []string) {
	info := schema.ProcessInfo{PID: int(pid), Exe: readExe(pid)}
	if cwd, err := readProcLink(pid, "cwd"); err == nil {
		info.Cwd = cwd
	}
	var ancestors []string
	if h.ProcessTable != nil {
		if entry := h.ProcessTable.Lookup(int(pid)); entry != nil {
			info.Comm = entry.Comm
			info.PPID = entry.PPid
		}
		ancestors = h.ancestorNames(pid)
	}
	return info, ancestors
}

// ancestorNames returns the exe basenames of the ancestors of pid, nearest
// first. This is what startedBy() matches against.
func (h *Handler) ancestorNames(pid uint32) []string {
	entries := h.ProcessTable.LookupAncestors(int(pid))
	if len(entries) == 0 {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, filepath.Base(entry.Exe))
	}
	return names
}

// denyUnresolved answers a notification whose path argument could not be
// resolved. This is not a policy outcome: it means the supervisor could not
// determine what the syscall was about, so it denies and says so.
//
// Keep this visible. A steady stream of these points at a decoding bug, not at
// a misconfigured policy, and it is easy to mistake for one when the audit log
// only shows a deny.
func (h *Handler) denyUnresolved(notifFd int, req *seccomp.SeccompNotif, ev *DecodedEvent, start time.Time) {
	syscallName := seccomp.SyscallName(int(req.Data.Nr))

	slog.Warn("deny unresolved path",
		"action", ev.Action,
		"syscall", syscallName,
		"raw", ev.UnresolvedRaw,
		"reason", ev.UnresolvedReason,
		"pid", req.Pid)

	msg := fmt.Sprintf("Cannot check %q because its location could not be determined, so it is blocked.", ev.UnresolvedRaw)
	DeliverMessage(req.Pid, msg)

	if h.Stats != nil {
		h.Stats.RecordDeny(string(ev.Action), ev.UnresolvedRaw, unresolvedRuleName)
	}

	if h.OnDecision != nil {
		rec := &schema.AuditRecord{
			Timestamp:        start.UTC(),
			Verdict:          policy.VerdictDeny,
			Errno:            "EACCES",
			Message:          msg,
			MessageDelivered: true,
			LatencyUs:        time.Since(start).Microseconds(),
			Unresolved:       ev.UnresolvedReason,
		}
		rec.Event.Action = ev.Action
		rec.Event.RequestedPath = ev.UnresolvedRaw
		// This is a denial, so it is enriched like any other: these records are
		// the ones that need explaining, and they should be rare.
		procInfo, ancestors := h.processContext(req.Pid)
		if tgid, ok := readTgid(req.Pid); ok {
			procInfo.TGID = int(tgid)
		}
		rec.Event.Process = procInfo
		rec.Event.Ancestors = ancestors
		rec.Event.Sandbox = h.Sandbox
		rec.Event.Syscall.Name = syscallName
		rec.Rule = &schema.RuleRef{Name: unresolvedRuleName}
		h.OnDecision(rec)
	}

	resp := &seccomp.SeccompNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
	seccomp.NotifSend(notifFd, resp)
}

// unresolvedRuleName labels denials caused by failed path resolution so they can
// be told apart from rule-driven denials in stats and audit output.
const unresolvedRuleName = "<unresolved-path>"

// cacheTarget extracts the target string for a cache key from a decoded event.
func cacheTarget(ev DecodedEvent) string {
	if ev.Path != "" {
		return ev.Path
	}
	if ev.Socket != "" {
		return ev.Socket
	}
	if ev.Host != "" {
		return fmt.Sprintf("%s:%d", ev.Host, ev.Port)
	}
	return ""
}

// denyErrno returns the errno to use when denying a syscall. It uses the
// custom errno from the rule if set, otherwise a sensible default per action.
func denyErrno(action policy.Action, errnoStr string) unix.Errno {
	if errnoStr != "" {
		if e := lookupErrno(errnoStr); e != 0 {
			return e
		}
	}
	return lookupErrno(defaultErrnoName(action))
}

// defaultErrnoName is the errno a denial returns when no rule names one.
// ECONNREFUSED for connect because a blocked connection should look like a
// refused one, EACCES everywhere else.
func defaultErrnoName(action policy.Action) string {
	if action == policy.ActionConnect {
		return "ECONNREFUSED"
	}
	return "EACCES"
}

// recordErrno returns the errno name the process actually receives. A default
// deny carries no rule and therefore no errno, but the syscall still fails with
// one, and a record that omits it does not describe what happened.
func recordErrno(action policy.Action, ruleErrno string) string {
	if ruleErrno != "" && lookupErrno(ruleErrno) != 0 {
		return strings.ToUpper(strings.TrimSpace(ruleErrno))
	}
	return defaultErrnoName(action)
}

// lookupErrno converts an errno name string (e.g. "EACCES", "EROFS") to the
// corresponding unix.Errno value. Returns 0 if unknown.
func lookupErrno(name string) unix.Errno {
	name = strings.ToUpper(strings.TrimSpace(name))
	switch name {
	case "EPERM":
		return unix.EPERM
	case "ENOENT":
		return unix.ENOENT
	case "EIO":
		return unix.EIO
	case "EACCES":
		return unix.EACCES
	case "EEXIST":
		return unix.EEXIST
	case "ENOTDIR":
		return unix.ENOTDIR
	case "EISDIR":
		return unix.EISDIR
	case "EINVAL":
		return unix.EINVAL
	case "ENFILE":
		return unix.ENFILE
	case "EMFILE":
		return unix.EMFILE
	case "ENOSPC":
		return unix.ENOSPC
	case "EROFS":
		return unix.EROFS
	case "ENOSYS":
		return unix.ENOSYS
	case "ECONNREFUSED":
		return unix.ECONNREFUSED
	case "ENETUNREACH":
		return unix.ENETUNREACH
	case "ENOTSUP", "EOPNOTSUPP":
		return unix.EOPNOTSUPP
	default:
		return 0
	}
}

// Run receives and handles notifications in a loop until the fd becomes
// unreadable (child exited, fd closed). It polls with a timeout to avoid
// blocking the goroutine indefinitely.
func (h *Handler) Run(notifFd int) {
	for {
		fds := []unix.PollFd{{Fd: int32(notifFd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			slog.Error("handler poll error, exiting", "error", err)
			return
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
			slog.Error("handler poll revents, exiting", "revents", fds[0].Revents)
			return
		}

		req, err := seccomp.NotifRecv(notifFd)
		if err != nil {
			if err == unix.EINTR || err == unix.ENOENT {
				continue
			}
			slog.Error("handler notif recv error, exiting", "error", err)
			return
		}

		go h.HandleSyscall(notifFd, req)
	}
}

// readExe reads the executable path for a pid from /proc/<pid>/exe.
// Returns an empty string on error.
func readExe(pid uint32) string {
	target, err := readlinkExe(pid)
	if err != nil {
		return ""
	}
	return target
}

// readlinkExe resolves /proc/<pid>/exe.
func readlinkExe(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
