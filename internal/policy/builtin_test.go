// builtin_test.go tests that built-in protection rules compile and evaluate correctly.
package policy

import (
	"testing"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

const (
	testOwnSock   = "/run/user/1000/gravelpit/supervisor-abc123.sock"
	testOtherSock = "/run/user/1000/gravelpit/supervisor-def456.sock"
)

func TestBuiltinRules(t *testing.T) {
	t.Setenv(rpc.EnvSockPath, testOwnSock)
	rules, err := BuiltinRules()
	if err != nil {
		t.Fatalf("BuiltinRules() error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 built-in rules, got %d", len(rules))
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	for _, want := range []string{"protect-gravelpit-files", "protect-gravelpit-socket", "allow-own-supervisor-socket"} {
		if !names[want] {
			t.Errorf("%s rule missing", want)
		}
	}
}

// Own socket must be allowed (for "gravelpit status"), other sessions' sockets
// must be denied. A user deny for the same directory must not override the allow.
func TestSupervisorSocketAccess(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv(rpc.EnvSockPath, testOwnSock)

	builtins, err := BuiltinRules()
	if err != nil {
		t.Fatalf("BuiltinRules() error: %v", err)
	}

	loader, err := NewLoader()
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	userYAML := `
- name: user-deny-gravelpit-socket
  action: connect
  verdict: deny
  match: >
    family == "AF_UNIX" && (
      pathMatch(socket, "$XDG_RUNTIME_DIR/gravelpit/**") ||
      pathMatch(socket, "/tmp/gravelpit-*/**")
    )
`
	userRules, errs := loader.LoadBytes([]byte(userYAML), "<test>")
	if len(errs) > 0 {
		t.Fatalf("loading user rules: %v", errs[0])
	}

	engine := NewEngine(append(builtins, userRules...))

	d := engine.Evaluate(&Event{Action: ActionConnect, Family: "AF_UNIX", Socket: testOwnSock})
	if d.Verdict != VerdictAllow {
		rule := "<none>"
		if d.Rule != nil {
			rule = d.Rule.Name
		}
		t.Errorf("own socket: got %s (rule %s), want allow", d.Verdict, rule)
	}

	d = engine.Evaluate(&Event{Action: ActionConnect, Family: "AF_UNIX", Socket: testOtherSock})
	if d.Verdict != VerdictDeny {
		rule := "<none>"
		if d.Rule != nil {
			rule = d.Rule.Name
		}
		t.Errorf("other socket: got %s (rule %s), want deny", d.Verdict, rule)
	}
}
