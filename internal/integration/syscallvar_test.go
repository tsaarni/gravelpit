// syscallvar_test.go verifies the CEL "syscall" variable end to end, including
// the cache correctness problem it creates: open and openat produce the same
// action for the same path, so a cached verdict must not be shared between them.
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// probeSyscallVar opens the same file twice, first with openat and then with the
// legacy open. Both are action "read" on the same path, so they collide in the
// decision cache, whose key holds only the action and the target.
func probeSyscallVar(homeDir, workDir string) {
	target := filepath.Join(workDir, "shared.txt")

	tryOpen(target, unix.O_RDONLY)

	pathBytes, err := unix.BytePtrFromString(target)
	if err != nil {
		return
	}
	fd, _, errno := unix.Syscall(unix.SYS_OPEN,
		uintptr(unsafe.Pointer(pathBytes)), uintptr(unix.O_RDONLY), 0)
	if errno == 0 {
		unix.Close(int(fd))
	}
}

func TestSyscallVariableAndCacheCollision(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(workDir, "shared.txt")
	writeFile(t, target, "content")

	res := runSandbox(t, sandboxOpts{
		rules:    buildSyscallRules(t, target),
		probeSet: "syscallvar",
		homeDir:  homeDir,
		workDir:  workDir,
		// The cache is on, which is the point: without treating syscall as
		// uncacheable context, the second open would be served the first
		// verdict.
		cache: policy.NewCache(1000),
	})

	var got []*schema.AuditRecord
	for _, r := range res.records {
		if r.Path == target {
			got = append(got, r)
		}
	}
	for _, r := range got {
		rule := "default"
		if r.Rule != nil {
			rule = r.Rule.Name
		}
		t.Logf("  syscall=%-8s verdict=%-5s cache_hit=%-5v rule=%s", r.Syscall.Name, r.Verdict, r.CacheHit, rule)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records for %s, want 2 (openat and open)", len(got), target)
	}

	want := []struct {
		syscall string
		verdict policy.Verdict
	}{
		{"openat", policy.VerdictAllow},
		{"open", policy.VerdictDeny},
	}
	for i, w := range want {
		if got[i].Syscall.Name != w.syscall {
			t.Errorf("record %d syscall = %q, want %q", i, got[i].Syscall.Name, w.syscall)
			continue
		}
		if got[i].Verdict != w.verdict {
			t.Errorf("%s verdict = %s, want %s", w.syscall, got[i].Verdict, w.verdict)
		}
		if got[i].CacheHit {
			t.Errorf("%s was a cache hit: a syscall-dependent decision must not be cached", w.syscall)
		}
	}
}

// buildSyscallRules allows reads generally and denies only the legacy open of
// one file, so the verdict for a single path depends on which syscall asked.
func buildSyscallRules(t *testing.T, target string) []*policy.CompiledRule {
	t.Helper()

	yaml := fmt.Sprintf(`
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: deny-legacy-open
  action: read
  verdict: deny
  match: 'syscall.name == "open" && pathMatch(path, "%s")'
  message: "denied by deny-legacy-open"
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
`, target)

	l, err := policy.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "syscall_test.yaml")
	if len(errs) > 0 {
		t.Fatalf("loading rules: %v", errs)
	}
	return rules
}
