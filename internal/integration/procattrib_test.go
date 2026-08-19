// procattrib_test.go verifies that a process which exec'd another binary is
// attributed to the binary it became, both in audit records and in startedBy().
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tsaarni/gravelpit/internal/policy"
)

// probeExecChild runs "sh -c 'cat FILE; true'" so that two execs happen inside
// the sandbox: the probe execs sh, and sh forks and execs cat. The trailing
// "; true" matters: for a lone command sh execs it in place, which would collapse
// the chain to a single pid and leave nothing to attribute a parent to.
func probeExecChild(homeDir, workDir string) {
	target := filepath.Join(homeDir, "target.txt")
	cmd := exec.Command("/bin/sh", "-c", "cat "+target+"; true")
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func TestProcessAttributionAfterExec(t *testing.T) {
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skipf("cat not found: %v", err)
	}
	wantExe, err := filepath.EvalSymlinks(catPath)
	if err != nil {
		t.Fatal(err)
	}
	shExe, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("cannot resolve /bin/sh: %v", err)
	}
	// startedBy() matches the basename of an ancestor's exe.
	wantAncestor := filepath.Base(shExe)

	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(homeDir, "target.txt")
	writeFile(t, target, "content")

	res := runSandbox(t, sandboxOpts{
		rules:    buildAttributionRules(t, homeDir, wantAncestor),
		probeSet: "execchild",
		homeDir:  homeDir,
		workDir:  workDir,
	})

	var found bool
	for _, r := range res.records {
		if r.Path != target {
			continue
		}
		found = true
		t.Logf("record: verdict=%s exe=%s rule=%v", r.Verdict, r.Process.Exe, r.Rule)

		// The reader is cat, reached through two execs. Before the fix the table
		// recorded /proc/<pid>/exe at execve notification time, which is the
		// binary that called exec, so this reported the test binary.
		if r.Process.Exe != wantExe {
			self, _ := os.Readlink("/proc/self/exe")
			extra := ""
			if r.Process.Exe == self {
				extra = " (this is the test binary: identity captured before the exec took effect)"
			}
			t.Errorf("record exe = %q, want %q%s", r.Process.Exe, wantExe, extra)
		}

		// The allow rule requires startedBy(sh). Reaching allow proves ancestry
		// named the immediate parent correctly; before the fix every ancestor
		// name was shifted one exec back and this rule could not match.
		if r.Verdict != policy.VerdictAllow {
			t.Errorf("verdict = %s, want allow: startedBy(%q) did not match", r.Verdict, wantAncestor)
		}
	}
	if !found {
		t.Errorf("no audit record for %s; records: %d", target, len(res.records))
		for _, r := range res.records {
			t.Logf("  %s %s", r.Verdict, r.Path)
		}
	}
}

// buildAttributionRules denies reads under the home dir and allows the target
// file back only for a process started by ancestor. The allow pattern names more
// literal characters than the deny, so it wins on specificity.
//
// These go through the loader rather than CompileRule directly, because
// startedBy() is rewritten into an ancestors lookup at load time and does not
// exist as a CEL function.
func buildAttributionRules(t *testing.T, homeDir, ancestor string) []*policy.CompiledRule {
	t.Helper()

	yaml := fmt.Sprintf(`
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: deny-home-reads
  action: read
  verdict: deny
  match: 'pathMatch(path, "%[1]s/**")'
  message: "denied by deny-home-reads"
- name: allow-target-for-shell-children
  action: read
  verdict: allow
  match: 'startedBy("%[2]s") && pathMatch(path, "%[1]s/target.txt")'
- name: allow-exec
  action: exec
  verdict: allow
  match: "true"
- name: allow-writes
  action: [write, delete]
  verdict: allow
  match: "true"
- name: allow-connect
  action: connect
  verdict: allow
  match: "true"
`, homeDir, ancestor)

	l, err := policy.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "attribution_test.yaml")
	if len(errs) > 0 {
		t.Fatalf("loading rules: %v", errs)
	}
	return rules
}
