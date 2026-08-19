// examples_test.go validates that example policy files in policies/examples/ load and compile.
package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tsaarni/gravelpit/internal/policy"
)

// TestExamplePolicies loads the example policy set and verifies key verdicts.
// This replaces the old CLI-based "gravelpit policy test" command — these are
// the same scenarios, expressed as a regular Go test.
func TestExamplePolicies(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/testuser"
	}

	vars := map[string]string{
		"$HOME":            home,
		"$XDG_DATA_HOME":   filepath.Join(home, ".local/share"),
		"$XDG_STATE_HOME":  filepath.Join(home, ".local/state"),
		"$XDG_RUNTIME_DIR": "/run/user/1000",
		"$WORKDIR":         filepath.Join(home, "work"),
		"$TMPDIR":          "/tmp",
	}

	loader, err := policy.NewLoader(policy.WithVariables(vars))
	if err != nil {
		t.Fatal(err)
	}

	rules, errs := loader.LoadDir("../../policies/examples")
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("load error: %v", e)
		}
		t.FailNow()
	}

	engine := policy.NewEngine(rules)

	type testCase struct {
		desc   string
		action policy.Action
		path   string
		socket string
		host   string
		port   int
		family string
		want   policy.Verdict
		wantBy string // rule name or "default"
	}

	expand := func(s string) string {
		for k, v := range vars {
			s = replaceAll(s, k, v)
		}
		return s
	}

	cases := []testCase{
		// Secrets that must stay blocked (no rule allows them).
		{"ssh private key", policy.ActionRead, expand("$HOME/.ssh/id_rsa"), "", "", 0, "", policy.VerdictDeny, "block-hidden-files"},
		{"aws credentials", policy.ActionRead, expand("$HOME/.aws/credentials"), "", "", 0, "", policy.VerdictDeny, "block-hidden-files"},
		{"gh token", policy.ActionRead, expand("$HOME/.config/gh/hosts.yml"), "", "", 0, "", policy.VerdictDeny, "block-hidden-files"},
		{"docker credentials", policy.ActionRead, expand("$HOME/.docker/config.json"), "", "", 0, "", policy.VerdictDeny, "block-hidden-files"},
		{"unknown tool token", policy.ActionRead, expand("$HOME/.newtool/token"), "", "", 0, "", policy.VerdictDeny, "block-hidden-files"},

		// Allowed reads.
		{"workspace file", policy.ActionRead, expand("$HOME/work/main.go"), "", "", 0, "", policy.VerdictAllow, "reads-allowed"},
		{"build cache", policy.ActionRead, expand("$HOME/.cache/go-build/ab/x"), "", "", 0, "", policy.VerdictAllow, "read-build-caches"},
		{"ssh public key", policy.ActionRead, expand("$HOME/.ssh/id_ed25519.pub"), "", "", 0, "", policy.VerdictAllow, "read-ssh-public-parts"},
		{"git config", policy.ActionRead, expand("$HOME/.config/git/config"), "", "", 0, "", policy.VerdictAllow, "read-tool-settings"},

		// dir/** matches dir itself (opening a directory is ordinary openat).
		{"cache dir itself", policy.ActionRead, expand("$HOME/.cache"), "", "", 0, "", policy.VerdictAllow, "read-build-caches"},

		// Writes.
		{"write workspace", policy.ActionWrite, expand("$HOME/work/main.go"), "", "", 0, "", policy.VerdictAllow, "workspace-and-scratch"},
		{"write /tmp", policy.ActionWrite, "/tmp/build/out", "", "", 0, "", policy.VerdictAllow, "workspace-and-scratch"},
		{"write home root", policy.ActionWrite, expand("$HOME/notes.txt"), "", "", 0, "", policy.VerdictDeny, "default"},

		// Gravelpit self-protection.
		{"write gravelpit policy", policy.ActionWrite, expand("$HOME/.config/gravelpit/policies/x.yaml"), "", "", 0, "", policy.VerdictDeny, "protect-gravelpit-files"},
		{"write audit log", policy.ActionWrite, expand("$HOME/.local/share/gravelpit/audit.jsonl"), "", "", 0, "", policy.VerdictDeny, "protect-gravelpit-files"},

		// Autorun protection.
		{"write bashrc", policy.ActionWrite, expand("$HOME/.bashrc"), "", "", 0, "", policy.VerdictDeny, "protect-autorun-files"},
		{"delete bashrc", policy.ActionDelete, expand("$HOME/.bashrc"), "", "", 0, "", policy.VerdictDeny, "protect-autorun-files"},

		// Most-specific-wins: allow-cache beats block-hidden.
		{"cache beats hidden", policy.ActionRead, expand("$HOME/.cache/go-build/x"), "", "", 0, "", policy.VerdictAllow, "read-build-caches"},
		// Most-specific-wins: protect-gravelpit beats tool-state.
		{"gravelpit beats tool-state", policy.ActionWrite, expand("$HOME/.config/gravelpit/policies/a.yaml"), "", "", 0, "", policy.VerdictDeny, "protect-gravelpit-files"},

		// Connect.
		{"tcp egress", policy.ActionConnect, "", "", "140.82.121.4", 443, "AF_INET", policy.VerdictAllow, "network-allowed"},
		{"unix docker", policy.ActionConnect, "", "/run/docker.sock", "", 0, "AF_UNIX", policy.VerdictAllow, "sockets-allowed"},
		{"unix dbus blocked", policy.ActionConnect, "", "/run/user/1000/bus", "", 0, "AF_UNIX", policy.VerdictDeny, "block-keyring-sockets"},
		{"keyring ssh allowed", policy.ActionConnect, "", "/run/user/1000/keyring/ssh", "", 0, "AF_UNIX", policy.VerdictAllow, "allow-keyring-ssh-agents"},
		{"gravelpit socket blocked", policy.ActionConnect, "", "/run/user/1000/gravelpit/supervisor.sock", "", 0, "AF_UNIX", policy.VerdictDeny, "protect-gravelpit-socket"},

		// Metadata.
		{"chmod workspace", policy.ActionMetadata, expand("$HOME/work/build.sh"), "", "", 0, "", policy.VerdictAllow, "chmod-in-writable-paths"},
		{"chmod secret", policy.ActionMetadata, expand("$HOME/.ssh/id_rsa"), "", "", 0, "", policy.VerdictDeny, "chmod-wont-help"},

		// Exec (not restricted).
		{"exec git", policy.ActionExec, "/usr/bin/git", "", "", 0, "", policy.VerdictAllow, "exec-allowed"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ev := &policy.Event{
				Action: tc.action,
				Path:   tc.path,
				Socket: tc.socket,
				Host:   tc.host,
				Port:   tc.port,
				Family: tc.family,
			}
			d := engine.Evaluate(ev)
			if d.Verdict != tc.want {
				t.Errorf("got %s, want %s", d.Verdict, tc.want)
			}
			gotBy := "default"
			if d.Rule != nil {
				gotBy = d.Rule.Name
			}
			if gotBy != tc.wantBy {
				t.Errorf("decided by %q, want %q", gotBy, tc.wantBy)
			}
		})
	}
}

func replaceAll(s, old, new string) string {
	for {
		i := indexOf(s, old)
		if i < 0 {
			return s
		}
		s = s[:i] + new + s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
