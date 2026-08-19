// eval_test.go covers the diagnostics that policy eval reports: which rules
// could not be tested, and the machine-readable form of the result.
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContextRefs(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		{`pathMatch(path, "/tmp/**")`, nil},
		{`process.exe == "/usr/bin/ssh"`, []string{"process.exe"}},
		{`process.exe == "/x" && process.cwd == "/y"`, []string{"process.exe", "process.cwd"}},
		{`"git" in ancestors`, []string{"ancestors"}},
		{`sandbox.workdir != ""`, []string{"sandbox.workdir"}},
		{`has(process)`, []string{"process"}},
		// A word inside a string literal is data, not a reference.
		{`pathMatch(path, "/var/lib/process/sandbox")`, nil},
		// A longer identifier that merely starts with a keyword is not a match.
		{`processed == "x"`, nil},
	}
	for _, tc := range tests {
		got := contextRefs(tc.expr)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("contextRefs(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestUnsuppliedContext(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/tmp/x", Process: ProcessInfo{Exe: "/usr/bin/ssh"}}

	if got := UnsuppliedContext(`process.exe == "/usr/bin/ssh"`, ev); len(got) != 0 {
		t.Errorf("got %v, want none: process.exe was supplied", got)
	}
	got := UnsuppliedContext(`process.exe == "/x" && process.cwd == "/y" && "git" in ancestors`, ev)
	want := []string{"process.cwd", "ancestors"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

// An unmatched rule that reads context the caller did not supply must say so.
// Otherwise "does not apply to this path" and "could not be tested" look the
// same, which is what made eval misleading for process.exe rules.
func TestEvalMarksUntestedRules(t *testing.T) {
	rules := []Rule{
		{Name: "block-hidden", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `pathMatch(path, "/home/user/.*/**")`},
		{Name: "ssh-keys", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `process.exe == "/usr/bin/ssh" && pathMatch(path, "/home/user/.ssh/id_*")`},
		{Name: "elsewhere", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `pathMatch(path, "/opt/**")`},
	}
	ev := &Event{Action: ActionRead, Path: "/home/user/.ssh/id_rsa", RequestedPath: "/home/user/.ssh/id_rsa"}
	r := Eval(compileTestRules(t, rules), ev)

	if r.Verdict != VerdictDeny || r.Rule == nil || r.Rule.Name != "block-hidden" {
		t.Fatalf("verdict = %s by %v, want deny by block-hidden", r.Verdict, r.Rule)
	}
	untested := map[string][]string{}
	for _, m := range r.Unmatched {
		untested[m.Rule.Name] = m.Untested
	}
	if got := untested["ssh-keys"]; len(got) != 1 || got[0] != "process.exe" {
		t.Errorf("ssh-keys untested = %v, want [process.exe]", got)
	}
	if got, ok := untested["elsewhere"]; !ok || len(got) != 0 {
		t.Errorf("elsewhere untested = %v, want empty: it reads no context", got)
	}

	text := FormatEval(r)
	if !strings.Contains(text, "not tested: process.exe empty") {
		t.Errorf("FormatEval output missing the untested marker:\n%s", text)
	}
}

// The canonical path is what the runtime matches, so eval has to show both when
// they differ. Reporting only the typed path is how eval could name a rule the
// runtime never consults.
func TestFormatEvalShowsRequestedAndCanonical(t *testing.T) {
	rules := []Rule{
		{Name: "allow-tmp", Actions: []Action{ActionWrite}, Verdict: VerdictAllow,
			Match: `pathMatch(path, "/tmp/**")`},
	}
	ev := &Event{
		Action:        ActionWrite,
		Path:          "/home/user/.config/gravelpit/policies/evil.yaml",
		RequestedPath: "/tmp/gp-escape/policies/evil.yaml",
	}
	text := FormatEval(Eval(compileTestRules(t, rules), ev))

	for _, want := range []string{
		"target: /home/user/.config/gravelpit/policies/evil.yaml",
		"as requested: /tmp/gp-escape/policies/evil.yaml",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}

	// When the two agree, the extra lines are noise.
	ev2 := &Event{Action: ActionWrite, Path: "/tmp/x", RequestedPath: "/tmp/x"}
	if text2 := FormatEval(Eval(compileTestRules(t, rules), ev2)); strings.Contains(text2, "as requested") {
		t.Errorf("output should not mention the requested path when it equals the target:\n%s", text2)
	}
}

func TestFormatEvalJSON(t *testing.T) {
	rules := []Rule{
		{Name: "block-hidden", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `pathMatch(path, "/home/user/.*/**")`, File: "reads.yaml", Line: 28},
		{Name: "ssh-keys", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `process.exe == "/usr/bin/ssh" && pathMatch(path, "/home/user/.ssh/id_*")`,
			File:  "reads.yaml", Line: 40},
	}
	ev := &Event{Action: ActionRead, Path: "/home/user/.ssh/id_rsa", RequestedPath: "/home/user/.ssh/id_rsa"}

	out, err := FormatEvalJSON(Eval(compileTestRules(t, rules), ev))
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Action    string `json:"action"`
		Target    string `json:"target"`
		Requested string `json:"requested"`
		Verdict   string `json:"verdict"`
		Score     int    `json:"score"`
		DecidedBy *struct {
			Name string `json:"name"`
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"decided_by"`
		Rules []struct {
			Name     string   `json:"name"`
			Matched  bool     `json:"matched"`
			Line     int      `json:"line"`
			Untested []string `json:"untested"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if got.Action != "read" || got.Verdict != "deny" || got.Score <= 0 {
		t.Errorf("action/verdict/score = %s/%s/%d, want read/deny with a positive score", got.Action, got.Verdict, got.Score)
	}
	if got.Requested != "" {
		t.Errorf("requested = %q, want omitted when equal to target", got.Requested)
	}
	if got.DecidedBy == nil || got.DecidedBy.Name != "block-hidden" || got.DecidedBy.Line != 28 {
		t.Errorf("decided_by = %+v, want block-hidden at line 28", got.DecidedBy)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(got.Rules))
	}
	for _, r := range got.Rules {
		if r.Name == "ssh-keys" {
			if r.Matched || len(r.Untested) != 1 || r.Untested[0] != "process.exe" {
				t.Errorf("ssh-keys = %+v, want unmatched with untested [process.exe]", r)
			}
		}
	}
}

// Default deny has no rule, and the JSON form has to be explicit about that
// rather than inventing one.
func TestFormatEvalJSONDefaultDeny(t *testing.T) {
	rules := []Rule{
		{Name: "allow-tmp", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `pathMatch(path, "/tmp/**")`},
	}
	ev := &Event{Action: ActionRead, Path: "/etc/shadow", RequestedPath: "/etc/shadow"}
	out, err := FormatEvalJSON(Eval(compileTestRules(t, rules), ev))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["verdict"] != "deny" {
		t.Errorf("verdict = %v, want deny", got["verdict"])
	}
	if got["decided_by"] != nil {
		t.Errorf("decided_by = %v, want null for default deny", got["decided_by"])
	}
}

func TestSyscallMatching(t *testing.T) {
	rules := []Rule{
		{Name: "allow-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `true`},
		{Name: "deny-legacy-open", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `syscall.name == "open" && pathMatch(path, "/tmp/x")`},
	}
	e := NewEngine(compileTestRules(t, rules))

	openat := e.Evaluate(&Event{Action: ActionRead, Path: "/tmp/x",
		Syscall: SyscallInfo{Name: "openat", Number: 257}})
	if openat.Verdict != VerdictAllow {
		t.Errorf("openat verdict = %s, want allow", openat.Verdict)
	}
	legacy := e.Evaluate(&Event{Action: ActionRead, Path: "/tmp/x",
		Syscall: SyscallInfo{Name: "open", Number: 2}})
	if legacy.Verdict != VerdictDeny {
		t.Errorf("open verdict = %s, want deny", legacy.Verdict)
	}
}

// A rule reading syscall must bypass the cache, because open, openat and
// openat2 all produce action "read" for the same path and the cache key cannot
// tell them apart. It must not, however, make the handler read /proc: the
// syscall is already decoded.
func TestSyscallRuleBypassesCacheButNeedsNoProcfs(t *testing.T) {
	rules := []Rule{
		{Name: "allow-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `true`},
		{Name: "deny-legacy-open", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `syscall.name == "open" && pathMatch(path, "/tmp/gated/**")`},
	}
	e := NewEngine(compileTestRules(t, rules))

	if e.CacheableTarget(ActionRead, "/tmp/gated/x") {
		t.Error("target inside the gate must not be cacheable: the verdict depends on the syscall")
	}
	if e.NeedsProcessContext(ActionRead, "/tmp/gated/x") {
		t.Error("a syscall-only rule must not trigger /proc reads")
	}
	// The gate still limits the reach of the rule.
	if !e.CacheableTarget(ActionRead, "/tmp/other") {
		t.Error("target outside the gate should stay cacheable")
	}
}

func TestSyscallUnsuppliedInEval(t *testing.T) {
	rules := []Rule{
		{Name: "deny-legacy-open", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `syscall.name == "open" && pathMatch(path, "/tmp/x")`},
	}
	// Without --syscall the rule is untestable rather than simply not
	// applicable, which is what the marker has to convey.
	r := Eval(compileTestRules(t, rules), &Event{Action: ActionRead, Path: "/tmp/x", RequestedPath: "/tmp/x"})
	if len(r.Unmatched) != 1 {
		t.Fatalf("got %d unmatched rules, want 1", len(r.Unmatched))
	}
	got := r.Unmatched[0].Untested
	if len(got) != 1 || got[0] != "syscall.name" {
		t.Errorf("untested = %v, want [syscall.name]", got)
	}
}

// Supplying context has to clear the [not tested] markers and let the rule
// decide. This is the whole point of the flags: before them, an exe rule could
// not be exercised at all.
func TestEvalContextClearsUntestedAndDecides(t *testing.T) {
	rules := []Rule{
		{Name: "ssh-keys", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `process.exe == "/usr/bin/ssh" && pathMatch(path, "/home/user/.ssh/id_*")`},
		{Name: "block-hidden", Actions: []Action{ActionRead}, Verdict: VerdictDeny,
			Match: `pathMatch(path, "/home/user/.*/**")`},
	}
	compiled := compileTestRules(t, rules)

	// Without context the deny wins and the exe rule is untestable.
	bare := &Event{Action: ActionRead, Path: "/home/user/.ssh/id_rsa", RequestedPath: "/home/user/.ssh/id_rsa"}
	if r := Eval(compiled, bare); r.Verdict != VerdictDeny {
		t.Fatalf("verdict without context = %s, want deny", r.Verdict)
	}

	ev := &Event{Action: ActionRead, Path: "/home/user/.ssh/id_rsa", RequestedPath: "/home/user/.ssh/id_rsa"}
	// /usr/bin/ssh need not exist here: an absent path is kept as given.
	if err := (EvalContext{Exe: "/usr/bin/ssh"}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	r := Eval(compiled, ev)
	if r.Verdict != VerdictAllow || r.Rule == nil || r.Rule.Name != "ssh-keys" {
		t.Errorf("verdict = %s by %v, want allow by ssh-keys", r.Verdict, r.Rule)
	}
	for _, m := range r.Unmatched {
		if len(m.Untested) > 0 {
			t.Errorf("rule %s still marked untested %v after context was supplied", m.Rule.Name, m.Untested)
		}
	}
}

// comm is truncated by the kernel on exec, so a rule comparing a longer name can
// never fire. eval has to truncate too, or it reports a match the runtime will
// never produce.
func TestEvalContextTruncatesComm(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Comm: "this-name-is-far-too-long"}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	if got := ev.Process.Comm; got != "this-name-is-fa" {
		t.Errorf("comm = %q (%d bytes), want %q truncated to 15", got, len(got), "this-name-is-fa")
	}
}

// comm follows from exe on exec, so supplying only --exe must still let a comm
// rule be evaluated rather than reported as untested.
func TestEvalContextDerivesCommFromExe(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Exe: "/usr/bin/ssh"}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Process.Comm != "ssh" {
		t.Errorf("comm = %q, want ssh derived from exe", ev.Process.Comm)
	}

	// An explicit comm wins, for a process renamed after exec.
	ev2 := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Exe: "/usr/bin/ssh", Comm: "other"}).Apply(ev2); err != nil {
		t.Fatal(err)
	}
	if ev2.Process.Comm != "other" {
		t.Errorf("comm = %q, want the explicit value to win", ev2.Process.Comm)
	}
}

// process.exe comes from /proc/<pid>/exe, which is fully resolved. A rule
// written against the symlink would never fire, so eval must resolve too.
func TestEvalContextResolvesExeSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "python3.11")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "python3")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// The temp dir itself may sit under a symlink, so compare against the
	// resolved form of the real path rather than the path as constructed.
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}

	ev := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Exe: link}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Process.Exe != want {
		t.Errorf("exe = %q, want %q: the symlink must be resolved", ev.Process.Exe, want)
	}
	if ev.Process.Comm != "python3.11" {
		t.Errorf("comm = %q, want python3.11: comm follows the resolved exe", ev.Process.Comm)
	}
}

// A relative path would be resolved against the caller's cwd, answering a
// question about a path the user did not ask about.
func TestEvalContextRejectsRelativePaths(t *testing.T) {
	for _, c := range []EvalContext{{Exe: "../bin/bash"}, {Cwd: "work"}} {
		ev := &Event{Action: ActionRead, Path: "/tmp/x"}
		if err := c.Apply(ev); err == nil {
			t.Errorf("Apply(%+v) succeeded, want an error about an absolute path", c)
		}
	}
}

// startedBy() compares exe basenames, so a full path has to be reduced to one.
func TestEvalContextAncestorsAreBasenames(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Ancestors: []string{"/usr/bin/git", "bash", "  "}}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "bash"}
	if strings.Join(ev.Ancestors, ",") != strings.Join(want, ",") {
		t.Errorf("ancestors = %v, want %v with empties dropped", ev.Ancestors, want)
	}
}

// The syscall name has to be validated, because eval is a debugging tool: a typo
// silently producing "no rule matched" is the failure it exists to prevent.
// Number is filled in so a rule reading syscall.number is testable too.
func TestEvalContextSyscall(t *testing.T) {
	ev := &Event{Action: ActionRead, Path: "/tmp/x"}
	if err := (EvalContext{Syscall: "openat2"}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Syscall.Name != "openat2" || ev.Syscall.Number == 0 {
		t.Errorf("syscall = %+v, want openat2 with a non-zero number", ev.Syscall)
	}

	ev2 := &Event{Action: ActionRead, Path: "/tmp/x"}
	err := (EvalContext{Syscall: "openat22"}).Apply(ev2)
	if err == nil {
		t.Fatal("unknown syscall accepted, want an error")
	}
	// The message must list what is accepted, or the user has to read the source.
	if !strings.Contains(err.Error(), "openat") {
		t.Errorf("error %q does not name the accepted syscalls", err)
	}
}

// Normalization is invisible unless eval reports what it evaluated with. A comm
// silently truncated to 15 bytes otherwise looks like a broken rule.
func TestFormatEvalShowsContext(t *testing.T) {
	rules := []Rule{
		{Name: "allow-tmp", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `pathMatch(path, "/tmp/**")`},
	}
	ev := &Event{Action: ActionRead, Path: "/tmp/x", RequestedPath: "/tmp/x"}
	if err := (EvalContext{Exe: "/usr/bin/ssh", Comm: "this-name-is-far-too-long", Ancestors: []string{"git"}, Syscall: "open"}).Apply(ev); err != nil {
		t.Fatal(err)
	}
	r := Eval(compileTestRules(t, rules), ev)

	text := FormatEval(r)
	for _, want := range []string{"context:", "process.exe", "/usr/bin/ssh", "this-name-is-fa", "ancestors", "git", "syscall.name", "open"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}

	out, err := FormatEvalJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Context map[string]string `json:"context"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Context["process.exe"] != "/usr/bin/ssh" || got.Context["process.comm"] != "this-name-is-fa" {
		t.Errorf("json context = %v, want the normalized exe and comm", got.Context)
	}

	// With no context supplied the section is noise and must not appear.
	bare := Eval(compileTestRules(t, rules), &Event{Action: ActionRead, Path: "/tmp/x", RequestedPath: "/tmp/x"})
	if strings.Contains(FormatEval(bare), "context:") {
		t.Error("context section printed when no context was supplied")
	}
	bareJSON, err := FormatEvalJSON(bare)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bareJSON, "\"context\"") {
		t.Errorf("json context present when no context was supplied:\n%s", bareJSON)
	}
}
