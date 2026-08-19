// engine_test.go tests the policy engine evaluation logic and rule precedence.
package policy

import "testing"

func compileTestRules(t testing.TB, rules []Rule) []*CompiledRule {
	t.Helper()
	env, err := NewCELEnv()
	if err != nil {
		t.Fatalf("NewCELEnv: %v", err)
	}
	var compiled []*CompiledRule
	for i := range rules {
		cr, err := CompileRule(env, &rules[i])
		if err != nil {
			t.Fatalf("CompileRule(%q): %v", rules[i].Name, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

func TestEngineBasicDeny(t *testing.T) {
	// No rules -> default deny.
	e := NewEngine(nil)
	d := e.Evaluate(&Event{Action: ActionRead, Path: "/etc/passwd"})
	if d.Verdict != VerdictDeny {
		t.Errorf("got %v, want deny", d.Verdict)
	}
	if d.Rule != nil {
		t.Errorf("expected nil rule for default deny, got %q", d.Rule.Name)
	}
}

func TestEngineSimpleAllow(t *testing.T) {
	rules := []Rule{
		{Name: "allow-all-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: "true"},
	}
	e := NewEngine(compileTestRules(t, rules))
	d := e.Evaluate(&Event{Action: ActionRead, Path: "/etc/passwd"})
	if d.Verdict != VerdictAllow {
		t.Errorf("got %v, want allow", d.Verdict)
	}
	if d.Rule.Name != "allow-all-reads" {
		t.Errorf("got rule %q, want allow-all-reads", d.Rule.Name)
	}
}

func TestEngineMostSpecificWins(t *testing.T) {
	rules := []Rule{
		{
			Name:    "allow-reads",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match:   "true",
		},
		{
			Name:    "block-hidden",
			Actions: []Action{ActionRead},
			Verdict: VerdictDeny,
			Match:   `pathMatch(path, "/home/user/.*") || pathMatch(path, "/home/user/.*/**")`,
		},
		{
			Name:    "allow-cache",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match:   `pathMatch(path, "/home/user/.cache/**")`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))

	tests := []struct {
		name     string
		path     string
		want     Verdict
		wantRule string
	}{
		{"normal file allowed", "/home/user/work/main.go", VerdictAllow, "allow-reads"},
		{"hidden file denied", "/home/user/.ssh/id_rsa", VerdictDeny, "block-hidden"},
		{"cache allowed (more specific)", "/home/user/.cache/go-build/x", VerdictAllow, "allow-cache"},
		{"cache dir itself allowed", "/home/user/.cache", VerdictAllow, "allow-cache"},
		{"hidden dir denied", "/home/user/.gnupg", VerdictDeny, "block-hidden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate(&Event{Action: ActionRead, Path: tt.path})
			if d.Verdict != tt.want {
				t.Errorf("path %q: got %v, want %v", tt.path, d.Verdict, tt.want)
			}
			if d.Rule == nil {
				t.Fatalf("path %q: got nil rule", tt.path)
			}
			if d.Rule.Name != tt.wantRule {
				t.Errorf("path %q: got rule %q, want %q", tt.path, d.Rule.Name, tt.wantRule)
			}
		})
	}
}

func TestEngineTieGoesToDeny(t *testing.T) {
	// Two rules, same score (both match:true -> score 0). Deny wins.
	rules := []Rule{
		{Name: "allow-all", Actions: []Action{ActionMetadata}, Verdict: VerdictAllow, Match: "true"},
		{Name: "deny-all", Actions: []Action{ActionMetadata}, Verdict: VerdictDeny, Match: "true"},
	}
	e := NewEngine(compileTestRules(t, rules))
	d := e.Evaluate(&Event{Action: ActionMetadata, Path: "/some/path"})
	if d.Verdict != VerdictDeny {
		t.Errorf("tie should go to deny, got %v", d.Verdict)
	}
	if d.Rule.Name != "deny-all" {
		t.Errorf("got rule %q, want deny-all", d.Rule.Name)
	}
}

func TestEngineConnectSocket(t *testing.T) {
	rules := []Rule{
		{
			Name:    "allow-unix",
			Actions: []Action{ActionConnect},
			Verdict: VerdictAllow,
			Match:   `family == "AF_UNIX"`,
		},
		{
			Name:    "block-bus",
			Actions: []Action{ActionConnect},
			Verdict: VerdictDeny,
			Match:   `family == "AF_UNIX" && pathMatch(socket, "/run/user/*/bus")`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))

	tests := []struct {
		name     string
		socket   string
		family   string
		want     Verdict
		wantRule string
	}{
		{"docker allowed", "/run/docker.sock", "AF_UNIX", VerdictAllow, "allow-unix"},
		{"bus blocked", "/run/user/1000/bus", "AF_UNIX", VerdictDeny, "block-bus"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate(&Event{
				Action: ActionConnect,
				Socket: tt.socket,
				Family: tt.family,
			})
			if d.Verdict != tt.want {
				t.Errorf("socket %q: got %v, want %v", tt.socket, d.Verdict, tt.want)
			}
			if d.Rule.Name != tt.wantRule {
				t.Errorf("socket %q: got rule %q, want %q", tt.socket, d.Rule.Name, tt.wantRule)
			}
		})
	}
}

func TestEngineConnectTCP(t *testing.T) {
	rules := []Rule{
		{
			Name:    "allow-tcp",
			Actions: []Action{ActionConnect},
			Verdict: VerdictAllow,
			Match:   `family == "AF_INET" || family == "AF_INET6"`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))

	d := e.Evaluate(&Event{
		Action: ActionConnect,
		Host:   "140.82.121.4",
		Port:   443,
		Family: "AF_INET",
	})
	if d.Verdict != VerdictAllow {
		t.Errorf("got %v, want allow", d.Verdict)
	}
}

func TestEngineMultiAction(t *testing.T) {
	// A rule applying to both write and delete.
	rules := []Rule{
		{
			Name:    "allow-workspace",
			Actions: []Action{ActionWrite, ActionDelete},
			Verdict: VerdictAllow,
			Match:   `pathMatch(path, "/home/user/work/**")`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))

	d := e.Evaluate(&Event{Action: ActionWrite, Path: "/home/user/work/main.go"})
	if d.Verdict != VerdictAllow {
		t.Errorf("write: got %v, want allow", d.Verdict)
	}

	d = e.Evaluate(&Event{Action: ActionDelete, Path: "/home/user/work/old.go"})
	if d.Verdict != VerdictAllow {
		t.Errorf("delete: got %v, want allow", d.Verdict)
	}

	// Outside workspace -> default deny (no rule matches).
	d = e.Evaluate(&Event{Action: ActionWrite, Path: "/home/user/notes.txt"})
	if d.Verdict != VerdictDeny {
		t.Errorf("outside workspace: got %v, want deny", d.Verdict)
	}
}

func TestEngineMessageInterpolation(t *testing.T) {
	rules := []Rule{
		{
			Name:    "deny-with-msg",
			Actions: []Action{ActionRead},
			Verdict: VerdictDeny,
			Match:   "true",
			Message: "Blocked: ${path}",
		},
	}
	e := NewEngine(compileTestRules(t, rules))
	d := e.Evaluate(&Event{Action: ActionRead, Path: "/secret/file"})
	if d.Message != "Blocked: /secret/file" {
		t.Errorf("got message %q, want %q", d.Message, "Blocked: /secret/file")
	}
}

func TestEngineDefaultErrno(t *testing.T) {
	rules := []Rule{
		{Name: "deny-no-errno", Actions: []Action{ActionRead}, Verdict: VerdictDeny, Match: "true"},
		{Name: "deny-custom-errno", Actions: []Action{ActionWrite}, Verdict: VerdictDeny, Match: "true", Errno: "EROFS"},
	}
	e := NewEngine(compileTestRules(t, rules))

	d := e.Evaluate(&Event{Action: ActionRead, Path: "/x"})
	if d.Errno != "EACCES" {
		t.Errorf("default errno: got %q, want EACCES", d.Errno)
	}

	d = e.Evaluate(&Event{Action: ActionWrite, Path: "/x"})
	if d.Errno != "EROFS" {
		t.Errorf("custom errno: got %q, want EROFS", d.Errno)
	}
}

func TestEngineCELError(t *testing.T) {
	// A rule that will error at runtime (accessing non-existent map key).
	// Should not match, and the fallback deny applies.
	rules := []Rule{
		{
			Name:    "bad-rule",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match:   `process.nonexistent == "foo"`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))
	d := e.Evaluate(&Event{Action: ActionRead, Path: "/some/file"})
	// The rule errors, doesn't match, and default deny applies.
	if d.Verdict != VerdictDeny {
		t.Errorf("CEL error should lead to deny, got %v", d.Verdict)
	}
}

func TestEngineProcessField(t *testing.T) {
	rules := []Rule{
		{
			Name:    "ssh-only",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match:   `process.exe == "/usr/bin/ssh"`,
		},
	}
	e := NewEngine(compileTestRules(t, rules))

	// Should allow when exe matches.
	d := e.Evaluate(&Event{
		Action:  ActionRead,
		Path:    "/home/user/.ssh/id_rsa",
		Process: ProcessInfo{Exe: "/usr/bin/ssh"},
	})
	if d.Verdict != VerdictAllow {
		t.Errorf("got %v, want allow", d.Verdict)
	}

	// Should deny when exe doesn't match.
	d = e.Evaluate(&Event{
		Action:  ActionRead,
		Path:    "/home/user/.ssh/id_rsa",
		Process: ProcessInfo{Exe: "/usr/bin/git"},
	})
	if d.Verdict != VerdictDeny {
		t.Errorf("got %v, want deny", d.Verdict)
	}
}

func TestEngineCacheableNoProcessRules(t *testing.T) {
	rules := []Rule{
		{Name: "allow-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `pathMatch(path, "/tmp/**")`},
		{Name: "deny-writes", Actions: []Action{ActionWrite}, Verdict: VerdictDeny, Match: `pathMatch(path, "/etc/**")`},
	}
	e := NewEngine(compileTestRules(t, rules))
	if !e.CacheableTarget(ActionRead, "/tmp/x") {
		t.Error("expected cacheable when no rules use process/ancestors/sandbox")
	}
	if e.NeedsProcessContext(ActionRead, "/tmp/x") {
		t.Error("expected no process context needed when no rules use it")
	}
}

// A process-dependent rule must only affect the actions it covers. Before this
// was per-action, one exec rule turned the cache off for every read.
func TestEngineCacheableProcessRuleIsPerAction(t *testing.T) {
	rules := []Rule{
		{Name: "allow-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `pathMatch(path, "/tmp/**")`},
		{Name: "process-rule", Actions: []Action{ActionExec}, Verdict: VerdictAllow, Match: `process.exe == "/usr/bin/git"`},
	}
	e := NewEngine(compileTestRules(t, rules))
	if e.CacheableTarget(ActionExec, "/usr/bin/git") {
		t.Error("expected exec to be uncacheable: an ungated exec rule reads process")
	}
	if !e.CacheableTarget(ActionRead, "/tmp/x") {
		t.Error("expected read to stay cacheable: no read rule reads process")
	}
}

// A process rule behind a path gate must only affect the targets that gate can
// match. This is what keeps a rule like allow-ssh-to-read-own-keys off the cost
// of every unrelated read.
func TestEngineCacheableGatedProcessRule(t *testing.T) {
	rules := []Rule{
		{Name: "allow-reads", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `pathMatch(path, "/tmp/**")`},
		{Name: "ssh-keys", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `process.exe == "/usr/bin/ssh" && pathMatch(path, "/home/user/.ssh/id_*")`},
	}
	e := NewEngine(compileTestRules(t, rules))

	tests := []struct {
		target    string
		cacheable bool
	}{
		{"/home/user/.ssh/id_rsa", false}, // gate matches, rule could apply
		{"/home/user/.ssh/config", true},  // same directory, gate does not match
		{"/usr/include/stdio.h", true},
		{"/tmp/x", true},
	}
	for _, tc := range tests {
		if got := e.CacheableTarget(ActionRead, tc.target); got != tc.cacheable {
			t.Errorf("CacheableTarget(read, %q) = %v, want %v", tc.target, got, tc.cacheable)
		}
		if got := e.NeedsProcessContext(ActionRead, tc.target); got == tc.cacheable {
			t.Errorf("NeedsProcessContext(read, %q) = %v, want %v", tc.target, got, !tc.cacheable)
		}
	}
}

// A pattern reached through || is not a requirement for the rule to match, so no
// gate can be proven and every target for the action stays uncacheable.
func TestEngineCacheableProcessRuleWithOrIsNotGated(t *testing.T) {
	rules := []Rule{
		{Name: "either", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `process.exe == "/usr/bin/ssh" || pathMatch(path, "/home/user/.ssh/id_*")`},
	}
	e := NewEngine(compileTestRules(t, rules))
	for _, target := range []string{"/home/user/.ssh/id_rsa", "/usr/include/stdio.h"} {
		if e.CacheableTarget(ActionRead, target) {
			t.Errorf("CacheableTarget(read, %q) = true, want false: || gives no required pattern", target)
		}
	}
}

// A parenthesized disjunction of patterns joined by && is still a gate: the
// target has to match one of them.
func TestEngineCacheableGateFromParenthesizedOr(t *testing.T) {
	rules := []Rule{
		{Name: "two-dirs", Actions: []Action{ActionRead}, Verdict: VerdictAllow,
			Match: `(pathMatch(path, "/a/**") || pathMatch(path, "/b/**")) && process.exe == "/usr/bin/ssh"`},
	}
	e := NewEngine(compileTestRules(t, rules))
	for _, target := range []string{"/a/x", "/b/y"} {
		if e.CacheableTarget(ActionRead, target) {
			t.Errorf("CacheableTarget(read, %q) = true, want false", target)
		}
	}
	if !e.CacheableTarget(ActionRead, "/c/z") {
		t.Error("CacheableTarget(read, /c/z) = false, want true: outside both gate patterns")
	}
}

func TestEngineCacheableWithAncestorsRule(t *testing.T) {
	rules := []Rule{
		{Name: "ancestors-rule", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `"node" in ancestors`},
	}
	e := NewEngine(compileTestRules(t, rules))
	if e.CacheableTarget(ActionRead, "/tmp/x") {
		t.Error("expected uncacheable when a rule uses ancestors")
	}
}

func TestEngineCacheableWithSandboxRule(t *testing.T) {
	rules := []Rule{
		{Name: "sandbox-rule", Actions: []Action{ActionRead}, Verdict: VerdictAllow, Match: `sandbox.workdir == "/home/user/project"`},
	}
	e := NewEngine(compileTestRules(t, rules))
	if e.CacheableTarget(ActionRead, "/tmp/x") {
		t.Error("expected uncacheable when a rule uses sandbox")
	}
}

func TestRequiredPatterns(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{"single gate", `process.exe == "/usr/bin/ssh" && pathMatch(path, "/h/.ssh/id_*")`, []string{"/h/.ssh/id_*"}},
		{"gate first", `pathMatch(path, "/h/.ssh/id_*") && process.exe == "/usr/bin/ssh"`, []string{"/h/.ssh/id_*"}},
		{"parenthesized or", `(pathMatch(path, "/a/**") || pathMatch(path, "/b/**")) && process.exe == "/x"`, []string{"/a/**", "/b/**"}},
		{"socket gate", `pathMatch(socket, "/run/foo") && process.exe == "/x"`, []string{"/run/foo"}},
		{"top level or", `process.exe == "/x" || pathMatch(path, "/a/**")`, nil},
		{"no pattern", `process.exe == "/x"`, nil},
		{"negated pattern", `!pathMatch(path, "/a/**") && process.exe == "/x"`, nil},
		{"pattern not a bare call", `process.exe == "/x" && (pathMatch(path, "/a/**") == false)`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := requiredPatterns(tc.expr)
			if len(got) != len(tc.want) {
				t.Fatalf("requiredPatterns(%q) = %v, want %v", tc.expr, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("requiredPatterns(%q) = %v, want %v", tc.expr, got, tc.want)
				}
			}
		})
	}
}
