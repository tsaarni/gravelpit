// observed_test.go verifies that a process which never exec'd inside the sandbox
// still gets attributed, from the /proc read the audit path already does.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/rpc"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// probeForkOnly makes the denied open happen in a process that forked but never
// exec'd: "( read x < FILE )" runs the redirect in a subshell, and read is a
// shell builtin, so no execve is intercepted for that pid. The trailing "; true"
// stops the shell from exec'ing the subshell body in place.
func probeForkOnly(homeDir, workDir string) {
	denied := filepath.Join(homeDir, "secret.txt")
	cmd := exec.Command("/bin/sh", "-c", "( read x < "+denied+" ) ; true")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Run()
}

func TestAttributionWithoutExec(t *testing.T) {
	shExe, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("cannot resolve /bin/sh: %v", err)
	}
	wantComm := filepath.Base(shExe)

	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(homeDir, "secret.txt")
	writeFile(t, denied, "secret")

	res := runSandbox(t, sandboxOpts{
		rules:    buildForkOnlyRules(t, denied),
		probeSet: "forkonly",
		homeDir:  homeDir,
		workDir:  workDir,
	})

	var rec *schema.AuditRecord
	for _, r := range res.records {
		if r.Path == denied {
			rec = r
			break
		}
	}
	if rec == nil {
		t.Fatalf("no record for %s (of %d records)", denied, len(res.records))
	}
	t.Logf("record: exe=%q comm=%q ppid=%d ancestors=%v",
		rec.Process.Exe, rec.Process.Comm, rec.Process.PPID, rec.Ancestors)

	// The subshell is still running the shell's binary, which is what /proc
	// reports for it.
	if rec.Process.Exe != shExe {
		t.Errorf("exe = %q, want %q", rec.Process.Exe, shExe)
	}
	// comm and ppid cannot come from the /proc exe read alone. They are here only
	// because the observation was stored in the process table.
	if rec.Process.Comm != wantComm {
		t.Errorf("comm = %q, want %q: the observed identity was not recorded", rec.Process.Comm, wantComm)
	}
	if rec.Process.PPID == 0 {
		t.Error("ppid = 0, want the pid of the shell that forked the subshell")
	}
	// With the entry in place the chain reaches the shell that forked it, which
	// is what startedBy() matches.
	if len(rec.Ancestors) == 0 {
		t.Error("ancestors is empty: the chain cannot start from a pid with no entry")
	} else if rec.Ancestors[0] != wantComm {
		t.Errorf("ancestors[0] = %q, want %q", rec.Ancestors[0], wantComm)
	}

	// The lookup that missed must be visible in the counters, since that is the
	// signal for sizing the table.
	processes := res.stats.Summary().Cache(rpc.CacheProcesses)
	if processes == nil {
		t.Fatal("summary has no process table stats")
	}
	if processes.Misses == 0 {
		t.Error("process table reports no misses, but a pid with no entry was looked up")
	}
	t.Logf("process table: entries=%d found=%d notFound=%d",
		processes.Entries, processes.Hits, processes.Misses)
}

// buildForkOnlyRules denies one file and allows everything else, with no rule
// reading process context so the record is built by the audit path alone.
func buildForkOnlyRules(t *testing.T, denied string) []*policy.CompiledRule {
	t.Helper()

	yaml := fmt.Sprintf(`
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: deny-secret
  action: read
  verdict: deny
  match: 'pathMatch(path, "%s")'
  message: "denied by deny-secret"
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
`, denied)

	l, err := policy.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "forkonly_test.yaml")
	if len(errs) > 0 {
		t.Fatalf("loading rules: %v", errs)
	}
	return rules
}
