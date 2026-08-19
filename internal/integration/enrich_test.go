// enrich_test.go verifies the process and sandbox detail carried by audit
// records, and that the allow path does not pay for the fields only a denial
// record needs.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// probeEnrich reads two files through a symlinked directory: one denied, one
// allowed. It goes through "sh -c ... ; true" so the reader is a process that
// exec'd inside the sandbox and therefore has a process table entry, which is
// where comm and ppid come from.
func probeEnrich(homeDir, workDir string) {
	denied := filepath.Join(homeDir, "link", "secret.txt")
	allowed := filepath.Join(homeDir, "link", "public.txt")
	cmd := exec.Command("/bin/sh", "-c", "cat "+denied+"; cat "+allowed+"; true")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Run()
}

func TestAuditRecordEnrichment(t *testing.T) {
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skipf("cat not found: %v", err)
	}
	catExe, err := filepath.EvalSymlinks(catPath)
	if err != nil {
		t.Fatal(err)
	}
	shExe, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("cannot resolve /bin/sh: %v", err)
	}

	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	realDir := filepath.Join(homeDir, "private")
	for _, d := range []string{workDir, realDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(realDir, "secret.txt"), "secret")
	writeFile(t, filepath.Join(realDir, "public.txt"), "public")
	// Canonicalization resolves the directory part of a path, so the symlink has
	// to be a directory for requested and canonical to differ.
	if err := os.Symlink(realDir, filepath.Join(homeDir, "link")); err != nil {
		t.Fatal(err)
	}

	sandboxInfo := schema.SandboxInfo{ID: "12345", Command: "sh -c cat", Workdir: workDir}

	res := runSandbox(t, sandboxOpts{
		rules:    buildEnrichRules(t, realDir),
		probeSet: "enrich",
		homeDir:  homeDir,
		workDir:  workDir,
		sandbox:  sandboxInfo,
	})

	deniedPath := filepath.Join(realDir, "secret.txt")
	allowedPath := filepath.Join(realDir, "public.txt")

	var denyRec, allowRec *schema.AuditRecord
	for _, r := range res.records {
		switch r.Path {
		case deniedPath:
			denyRec = r
		case allowedPath:
			allowRec = r
		}
	}
	if denyRec == nil || allowRec == nil {
		t.Fatalf("missing records: deny=%v allow=%v (of %d records)", denyRec != nil, allowRec != nil, len(res.records))
	}
	t.Logf("deny record: %+v", denyRec.Event)
	t.Logf("allow record: %+v", allowRec.Event)

	// The requested path is what the process named. Without it the symlink
	// rewrite is invisible in the log and the record looks like a denial of a
	// path nothing asked for.
	wantRequested := filepath.Join(homeDir, "link", "secret.txt")
	if denyRec.RequestedPath != wantRequested {
		t.Errorf("requested_path = %q, want %q", denyRec.RequestedPath, wantRequested)
	}
	// It is omitted when it adds nothing.
	if allowRec.RequestedPath != "" && allowRec.RequestedPath == allowRec.Path {
		t.Errorf("requested_path should be omitted when equal to path, got %q", allowRec.RequestedPath)
	}

	// Identity of the reader. cat exec'd inside the sandbox, so the table has it.
	if denyRec.Process.Exe != catExe {
		t.Errorf("exe = %q, want %q", denyRec.Process.Exe, catExe)
	}
	if want := filepath.Base(catExe); denyRec.Process.Comm != want {
		t.Errorf("comm = %q, want %q", denyRec.Process.Comm, want)
	}
	if denyRec.Process.PPID == 0 {
		t.Error("ppid = 0, want the pid of the shell that forked cat")
	}
	if denyRec.Process.Cwd == "" {
		t.Error("cwd is empty on a denial record")
	}
	if denyRec.Process.TGID == 0 {
		t.Error("tgid = 0: the notification pid is a thread id, the process id must be recorded too")
	}
	// startedBy() matches these names, and replaying a denial needs them.
	if len(denyRec.Ancestors) == 0 {
		t.Error("ancestors is empty on a denial record")
	} else if want := filepath.Base(shExe); denyRec.Ancestors[0] != want {
		t.Errorf("ancestors[0] = %q, want %q", denyRec.Ancestors[0], want)
	}

	// Sandbox identity is bound at startup, so every record carries it.
	for _, r := range []*schema.AuditRecord{denyRec, allowRec} {
		if r.Sandbox != sandboxInfo {
			t.Errorf("sandbox = %+v, want %+v", r.Sandbox, sandboxInfo)
		}
	}

	// The allow path stays lean: no rule here reads process context, so the
	// fields that cost a /proc read each are left out of allow records.
	if allowRec.Process.Cwd != "" {
		t.Errorf("allow record has cwd = %q, want empty: the allow path must not pay for it", allowRec.Process.Cwd)
	}
	if allowRec.Process.TGID != 0 {
		t.Errorf("allow record has tgid = %d, want 0", allowRec.Process.TGID)
	}
}

// buildEnrichRules denies one file and allows the other, both inside the same
// directory, with no rule reading process context.
func buildEnrichRules(t *testing.T, dir string) []*policy.CompiledRule {
	t.Helper()

	yaml := fmt.Sprintf(`
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: deny-secret
  action: read
  verdict: deny
  match: 'pathMatch(path, "%[1]s/secret.txt")'
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
`, dir)

	l, err := policy.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "enrich_test.yaml")
	if len(errs) > 0 {
		t.Fatalf("loading rules: %v", errs)
	}
	return rules
}
