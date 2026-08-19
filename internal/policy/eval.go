// eval.go implements the policy eval command logic.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tsaarni/gravelpit/internal/seccomp"
)

// EvalResult holds the output of evaluating a policy decision.
type EvalResult struct {
	Action  Action
	Verdict Verdict
	Rule    *Rule // nil for default deny
	Score   int
	// Requested is the target as the caller typed it, Target the one policy was
	// evaluated against. They differ when symlinks or procfs magic links were
	// resolved. The runtime decides on Target, so both are reported: a rule
	// edited on the basis of the requested path can be the wrong rule.
	Requested string
	Target    string
	// Context is the context the decision was evaluated with, after
	// normalization. Reporting it is what makes a surprising verdict
	// explainable: a comm truncated to 15 bytes, or a symlink-resolved exe,
	// otherwise looks like the rule is at fault.
	Context   []ContextValue
	Matched   []RuleMatch
	Unmatched []RuleMatch
}

// ContextValue is one context field the decision was evaluated with.
type ContextValue struct {
	Name  string
	Value string
}

// Eval evaluates an event against the given rules and returns a full
// breakdown of the decision including all matched and unmatched rules.
func Eval(rules []*CompiledRule, ev *Event) *EvalResult {
	engine := NewEngine(rules)
	decision, matches := engine.EvaluateWithDetails(ev)

	result := &EvalResult{
		Action:    ev.Action,
		Verdict:   decision.Verdict,
		Rule:      decision.Rule,
		Score:     decision.Score,
		Requested: ev.RequestedPath,
		Target:    evalTarget(ev),
		Context:   eventContext(ev),
	}

	for _, m := range matches {
		if m.Matched {
			result.Matched = append(result.Matched, m)
			continue
		}
		// A rule that reads context the caller did not supply was not tested.
		// Without this, an unmatched process.exe rule is indistinguishable from
		// one that genuinely does not apply to the target.
		m.Untested = UnsuppliedContext(m.Rule.Match, ev)
		result.Unmatched = append(result.Unmatched, m)
	}

	return result
}

// evalTarget returns the string the event was evaluated against.
func evalTarget(ev *Event) string {
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

// eventContext lists the context values the event carries. It reads the event
// rather than the caller's flags on purpose: what matters is the value the rules
// were evaluated against, not the one that was typed.
func eventContext(ev *Event) []ContextValue {
	var out []ContextValue
	add := func(name, value string) {
		if value != "" {
			out = append(out, ContextValue{Name: name, Value: value})
		}
	}
	add("process.exe", ev.Process.Exe)
	add("process.comm", ev.Process.Comm)
	add("process.cwd", ev.Process.Cwd)
	add("ancestors", strings.Join(ev.Ancestors, ", "))
	add("syscall.name", ev.Syscall.Name)
	return out
}

// FormatEval formats an EvalResult as human-readable text.
func FormatEval(r *EvalResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "action: %s\n", r.Action)
	fmt.Fprintf(&b, "target: %s\n", r.Target)
	if r.Requested != "" && r.Requested != r.Target {
		fmt.Fprintf(&b, "  as requested: %s\n", r.Requested)
		fmt.Fprintf(&b, "  (policy decides on the canonical path, which is what the supervisor evaluates)\n")
	}
	if len(r.Context) > 0 {
		fmt.Fprintf(&b, "context:\n")
		for _, c := range r.Context {
			fmt.Fprintf(&b, "  %-13s %s\n", c.Name, c.Value)
		}
	}
	fmt.Fprintf(&b, "verdict: %s\n", r.Verdict)
	if r.Rule != nil {
		fmt.Fprintf(&b, "decided by: %s (score %d, %s)\n", r.Rule.Name, r.Score, ruleLoc(r.Rule))
	} else {
		fmt.Fprintf(&b, "decided by: default deny (no rule matched)\n")
	}

	if len(r.Matched) > 0 {
		fmt.Fprintf(&b, "\nmatched rules:\n")
		for _, m := range r.Matched {
			fmt.Fprintf(&b, "  %3d  %-5s  %-30s  %s\n",
				m.Score, m.Rule.Verdict, m.Rule.Name, ruleLoc(m.Rule))
		}
	}

	if len(r.Unmatched) > 0 {
		fmt.Fprintf(&b, "\nunmatched rules:\n")
		for _, m := range r.Unmatched {
			fmt.Fprintf(&b, "       %-5s  %-30s  %s", m.Rule.Verdict, m.Rule.Name, ruleLoc(m.Rule))
			if len(m.Untested) > 0 {
				fmt.Fprintf(&b, "  [not tested: %s empty]", strings.Join(m.Untested, ", "))
			}
			b.WriteByte('\n')
		}
		if untestedCount(r.Unmatched) > 0 {
			fmt.Fprintf(&b, "\nRules marked [not tested] read process context that was not supplied,\n")
			fmt.Fprintf(&b, "so they cannot match here regardless of the policy. Supply it with\n")
			fmt.Fprintf(&b, "--exe, --comm, --cwd, --ancestors or --syscall to test them.\n")
		}
	}

	return b.String()
}

// untestedCount counts rules that could not be tested for lack of input.
func untestedCount(matches []RuleMatch) int {
	n := 0
	for _, m := range matches {
		if len(m.Untested) > 0 {
			n++
		}
	}
	return n
}

// ruleLoc renders the source location of a rule as file:line.
func ruleLoc(r *Rule) string {
	return fmt.Sprintf("%s:%d", filepath.Base(r.File), r.Line)
}

// evalJSON is the machine-readable form of an EvalResult. It is a separate type
// so the output shape is explicit and can be asserted in tests, rather than
// following struct changes in EvalResult by accident.
type evalJSON struct {
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Requested string            `json:"requested,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Verdict   string            `json:"verdict"`
	Score     int               `json:"score"`
	DecidedBy *evalRuleJSON     `json:"decided_by"` // null for default deny
	Rules     []evalRuleJSON    `json:"rules"`
}

type evalRuleJSON struct {
	Name     string   `json:"name"`
	Verdict  string   `json:"verdict"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Matched  bool     `json:"matched"`
	Score    int      `json:"score,omitempty"`
	Untested []string `json:"untested,omitempty"`
}

// FormatEvalJSON renders an EvalResult as JSON, so policy behaviour can be
// asserted by a test or a script instead of parsed out of the text form.
func FormatEvalJSON(r *EvalResult) (string, error) {
	out := evalJSON{
		Action:  string(r.Action),
		Target:  r.Target,
		Verdict: string(r.Verdict),
		Score:   r.Score,
		Rules:   make([]evalRuleJSON, 0, len(r.Matched)+len(r.Unmatched)),
	}
	if r.Requested != r.Target {
		out.Requested = r.Requested
	}
	if len(r.Context) > 0 {
		out.Context = make(map[string]string, len(r.Context))
		for _, c := range r.Context {
			out.Context[c.Name] = c.Value
		}
	}
	if r.Rule != nil {
		out.DecidedBy = &evalRuleJSON{
			Name:    r.Rule.Name,
			Verdict: string(r.Rule.Verdict),
			File:    r.Rule.File,
			Line:    r.Rule.Line,
			Matched: true,
			Score:   r.Score,
		}
	}
	for _, m := range append(append([]RuleMatch{}, r.Matched...), r.Unmatched...) {
		out.Rules = append(out.Rules, evalRuleJSON{
			Name:     m.Rule.Name,
			Verdict:  string(m.Rule.Verdict),
			File:     m.Rule.File,
			Line:     m.Rule.Line,
			Matched:  m.Matched,
			Score:    m.Score,
			Untested: m.Untested,
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// ParseTarget parses a CLI target string into Event fields.
// Variables ($HOME etc) are expanded. Syntax: a file path, tcp:HOST:PORT,
// tcp6:[HOST]:PORT, or unix:PATH.
func ParseTarget(action Action, target string) (*Event, error) {
	target = ExpandVars(target)
	ev := &Event{Action: action}

	switch {
	case strings.HasPrefix(target, "tcp:") || strings.HasPrefix(target, "tcp6:"):
		rest := target
		if strings.HasPrefix(rest, "tcp6:") {
			ev.Family = "AF_INET6"
			rest = rest[5:]
		} else {
			ev.Family = "AF_INET"
			rest = rest[4:]
		}
		lastColon := strings.LastIndex(rest, ":")
		if lastColon < 0 {
			return nil, fmt.Errorf("invalid tcp target %q: expected HOST:PORT", target)
		}
		ev.Host = rest[:lastColon]
		port := 0
		if _, err := fmt.Sscanf(rest[lastColon+1:], "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid port in %q: %w", target, err)
		}
		ev.Port = port

	case strings.HasPrefix(target, "unix:"):
		ev.Family = "AF_UNIX"
		ev.Socket = target[5:]

	default:
		ev.Path = target
		ev.RequestedPath = target
	}

	return ev, nil
}

// EvalContext is hypothetical process and syscall context supplied on the eval
// command line. Each field maps onto one Event field, so eval can exercise
// rules that read context the command cannot observe for itself.
type EvalContext struct {
	Exe       string
	Comm      string
	Cwd       string
	Ancestors []string
	Syscall   string
}

// Apply normalizes the supplied context and writes it into the event.
//
// Values are normalized into the form the runtime produces, so that a rule
// which cannot match a real process does not appear to match here:
//
//   - exe and cwd come from /proc/<pid>/{exe,cwd}, which are fully resolved, so
//     a symlinked path is resolved rather than matched as typed.
//   - comm is the exe basename truncated to 15 bytes, because the kernel
//     truncates on exec. A rule comparing a longer name can never fire.
//   - ancestors are exe basenames, which is what the process table stores and
//     what startedBy() compares against.
func (c EvalContext) Apply(ev *Event) error {
	if c.Exe != "" {
		exe, err := absResolved(ExpandVars(c.Exe), "exe")
		if err != nil {
			return err
		}
		ev.Process.Exe = exe
		// The kernel derives comm from exe on exec. Filling it in keeps a comm
		// rule and an exe rule from disagreeing about the same process, and
		// stops a comm rule being reported as untested when exe was given.
		ev.Process.Comm = kernelComm(exe)
	}
	// An explicit --comm wins, so a process whose comm was changed after exec
	// (prctl, or a thread name) can still be described.
	if c.Comm != "" {
		ev.Process.Comm = kernelComm(c.Comm)
	}
	if c.Cwd != "" {
		cwd, err := absResolved(ExpandVars(c.Cwd), "cwd")
		if err != nil {
			return err
		}
		ev.Process.Cwd = cwd
	}
	for _, a := range c.Ancestors {
		a = strings.TrimSpace(ExpandVars(a))
		if a == "" {
			continue
		}
		ev.Ancestors = append(ev.Ancestors, filepath.Base(a))
	}
	if c.Syscall != "" {
		nr, ok := seccomp.SyscallNumber(c.Syscall)
		if !ok {
			return fmt.Errorf("unknown syscall %q: the filter intercepts %s",
				c.Syscall, strings.Join(seccomp.SyscallNames(), ", "))
		}
		ev.Syscall = SyscallInfo{Name: c.Syscall, Number: nr}
	}
	return nil
}

// absResolved requires an absolute path and resolves symlinks in it.
//
// A path that does not exist here is kept as given rather than rejected: the
// policy may name a binary that is not installed on this machine, and refusing
// to evaluate it would make eval useless for that case. Relative input is an
// error instead, because resolving it against the caller's cwd would answer a
// question about a path the user did not ask about.
func absResolved(path, field string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path, the way /proc/<pid>/%s reports it: got %q", field, field, path)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	}
	return filepath.Clean(path), nil
}

// kernelComm derives comm the way the kernel does on exec: the basename,
// truncated to TASK_COMM_LEN-1 bytes. process.commFromExe does the same for the
// live process table; both must agree or eval and the runtime disagree.
func kernelComm(s string) string {
	comm := filepath.Base(s)
	if comm == "." || comm == "/" {
		return ""
	}
	const commTruncate = 15
	if len(comm) > commTruncate {
		comm = comm[:commTruncate]
	}
	return comm
}
