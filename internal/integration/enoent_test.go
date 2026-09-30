// enoent_test.go verifies that denying access to a non-existent file returns
// ENOENT instead of EACCES, matching what the kernel would have returned.
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
)

// probeEnoent exercises denied operations on existing and non-existing paths.
func probeEnoent(homeDir, _ string) {
	// Read existing hidden file -> deny with EACCES.
	tryOpen(filepath.Join(homeDir, ".secret", "token"), unix.O_RDONLY)
	// Read non-existent hidden file -> silent ENOENT, no audit record.
	tryOpen(filepath.Join(homeDir, ".nonexistent"), unix.O_RDONLY)
	// Delete existing hidden file -> deny with EACCES.
	_ = unix.Unlink(filepath.Join(homeDir, ".secret", "token"))
	// Delete non-existent hidden file -> silent ENOENT, no audit record.
	_ = unix.Unlink(filepath.Join(homeDir, ".secret", "gone"))
	// Write to non-existent hidden file -> deny with EACCES (not ENOENT,
	// because the process intended to create the file).
	tryOpen(filepath.Join(homeDir, ".newrc"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC)
}

func TestDenyNonExistentFileReturnsENOENT(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	secretDir := filepath.Join(homeDir, ".secret")
	for _, d := range []string{workDir, secretDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(secretDir, "token"), "s3cret")

	res := runSandbox(t, sandboxOpts{
		rules:    buildEnoentRules(t, homeDir),
		probeSet: "enoent",
		homeDir:  homeDir,
		workDir:  workDir,
	})

	for _, r := range res.records {
		rule := "default"
		if r.Rule != nil {
			rule = r.Rule.Name
		}
		t.Logf("  %-8s %-5s errno=%-10s %s  %s", r.Action, r.Verdict, r.Errno, r.Path, rule)
	}
	t.Logf("stderr:\n%s", res.stderr)

	// Existing file denials produce audit records with EACCES.
	existingToken := filepath.Join(secretDir, "token")
	for _, r := range res.records {
		if r.Path == existingToken && r.Verdict == policy.VerdictDeny && r.Errno != "EACCES" {
			t.Errorf("%s %s: errno = %q, want EACCES", r.Action, r.Path, r.Errno)
		}
	}

	// Write to non-existent file still gets EACCES (the process intended to
	// create the file, so ENOENT would be misleading).
	newrc := filepath.Join(homeDir, ".newrc")
	found := false
	for _, r := range res.records {
		if r.Path == newrc {
			found = true
			if r.Errno != "EACCES" {
				t.Errorf("write to non-existent file: errno = %q, want EACCES", r.Errno)
			}
		}
	}
	if !found {
		t.Error("write to non-existent hidden file should produce an audit record")
	}

	// Non-existent read/delete denials produce no audit record and no stderr
	// message. The early return sends ENOENT without any side effects.
	silentPaths := []string{
		filepath.Join(homeDir, ".nonexistent"),
		filepath.Join(secretDir, "gone"),
	}
	for _, p := range silentPaths {
		for _, r := range res.records {
			if r.Path == p {
				t.Errorf("unexpected audit record for non-existent path %q", p)
			}
		}
		if strings.Contains(res.stderr, p) {
			t.Errorf("stderr contains message for non-existent %q, want silent", p)
		}
	}
}

func buildEnoentRules(t *testing.T, homeDir string) []*policy.CompiledRule {
	t.Helper()

	yaml := fmt.Sprintf(`
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: block-hidden-reads
  action: read
  verdict: deny
  match: 'pathMatch(path, "%[1]s/.*") || pathMatch(path, "%[1]s/.*/**")'
  message: "Reading '${path}' is blocked."
- name: allow-exec
  action: exec
  verdict: allow
  match: "true"
- name: allow-connect
  action: connect
  verdict: allow
  match: "true"
- name: block-hidden-writes
  action: [write, delete]
  verdict: deny
  match: 'pathMatch(path, "%[1]s/.*") || pathMatch(path, "%[1]s/.*/**")'
  message: "Writing '${path}' is blocked."
`, homeDir)

	l, err := policy.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "enoent_test.yaml")
	if len(errs) > 0 {
		t.Fatalf("loading rules: %v", errs)
	}
	return rules
}
