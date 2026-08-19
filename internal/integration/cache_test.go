// cache_test.go verifies that a rule reading process context only bypasses the
// decision cache for the paths that rule can match.
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/rpc"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// TestCacheScopeWithProcessRule runs a policy holding one process-dependent read
// rule gated on "$HOME/.ssh/id_*" and checks three things at once:
//
//   - reads outside the gate are still cached, which is the whole point of
//     making cacheability per-target instead of per-policy
//   - reads inside the gate are never cached, since the verdict depends on who
//     is asking
//   - the gated rule still decides correctly, proving the handler gathers
//     process context for the targets that need it
//
// The sibling path .ssh/config is the interesting control: same directory as the
// gated path, denied by an unrelated rule, and still cacheable.
func TestCacheScopeWithProcessRule(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work", "project")
	secretDir := filepath.Join(homeDir, ".ssh")

	for _, d := range []string{workDir, secretDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(workDir, "main.go"), "package main\n")
	writeFile(t, filepath.Join(secretDir, "id_rsa"), "SECRET KEY")
	writeFile(t, filepath.Join(secretDir, "config"), "Host *\n")

	// The probe is a re-exec of this test binary, so its /proc/<pid>/exe is the
	// test binary with symlinks resolved.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probeExe, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}

	rules := buildTestRules(homeDir)
	rules = append(rules, compileRule(t, policy.Rule{
		Name:    "ssh-keys",
		Actions: []policy.Action{policy.ActionRead},
		Verdict: policy.VerdictAllow,
		Match: fmt.Sprintf(`process.exe == %q && pathMatch(path, "%s/.ssh/id_*")`,
			probeExe, homeDir),
	}))

	res := runSandbox(t, sandboxOpts{
		rules:    rules,
		probeSet: "cache",
		homeDir:  homeDir,
		workDir:  workDir,
		cache:    policy.NewCache(1000),
	})

	for _, r := range res.records {
		ruleName := "default"
		if r.Rule != nil {
			ruleName = r.Rule.Name
		}
		t.Logf("  %-5s cache_hit=%-5v %-30s %s", r.Verdict, r.CacheHit, ruleName, r.Path)
	}

	tests := []struct {
		desc         string
		path         string
		verdict      policy.Verdict
		rule         string
		wantCacheHit []bool // one entry per expected record, in order
	}{
		{
			desc:         "path outside the gate is cached on the second read",
			path:         filepath.Join(workDir, "main.go"),
			verdict:      policy.VerdictAllow,
			rule:         "allow-reads",
			wantCacheHit: []bool{false, true},
		},
		{
			desc:         "sibling of the gated path is still cached",
			path:         filepath.Join(secretDir, "config"),
			verdict:      policy.VerdictDeny,
			rule:         "block-hidden",
			wantCacheHit: []bool{false, true},
		},
		{
			desc:         "gated path is never cached and the process rule decides",
			path:         filepath.Join(secretDir, "id_rsa"),
			verdict:      policy.VerdictAllow,
			rule:         "ssh-keys",
			wantCacheHit: []bool{false, false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := recordsForPath(res.records, tc.path)
			if len(got) != len(tc.wantCacheHit) {
				t.Fatalf("got %d records for %s, want %d", len(got), tc.path, len(tc.wantCacheHit))
			}
			for i, r := range got {
				ruleName := ""
				if r.Rule != nil {
					ruleName = r.Rule.Name
				}
				if r.Verdict != tc.verdict || ruleName != tc.rule {
					t.Errorf("record %d: got %s by %q, want %s by %q", i, r.Verdict, ruleName, tc.verdict, tc.rule)
				}
				if r.CacheHit != tc.wantCacheHit[i] {
					t.Errorf("record %d: cache_hit = %v, want %v", i, r.CacheHit, tc.wantCacheHit[i])
				}
			}
		})
	}

	// The gated reads must not have been counted as cache lookups at all: an
	// uncacheable target skips both Get and Put.
	summary := res.stats.Summary()
	decisions := summary.Cache(rpc.CacheDecisions)
	if decisions == nil {
		t.Fatal("summary has no decision cache stats")
	}
	if decisions.Hits < 2 {
		t.Errorf("cache hits = %d, want at least 2 (one per cacheable repeated path)", decisions.Hits)
	}
	t.Logf("cache hits=%d misses=%d entries=%d bytes=%d",
		decisions.Hits, decisions.Misses, decisions.Entries, decisions.Bytes)
}

// probeCache reads three paths twice each: one outside the gated pattern, one
// sibling of the gated path, and the gated path itself.
func probeCache(homeDir, workDir string) {
	for i := 0; i < 2; i++ {
		tryOpen(filepath.Join(workDir, "main.go"), unix.O_RDONLY)
	}
	for i := 0; i < 2; i++ {
		tryOpen(filepath.Join(homeDir, ".ssh", "config"), unix.O_RDONLY)
	}
	for i := 0; i < 2; i++ {
		tryOpen(filepath.Join(homeDir, ".ssh", "id_rsa"), unix.O_RDONLY)
	}
}

// recordsForPath returns the records whose path is exactly path, in order.
func recordsForPath(records []*schema.AuditRecord, path string) []*schema.AuditRecord {
	var out []*schema.AuditRecord
	for _, r := range records {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// compileRule compiles a single rule for tests that add to buildTestRules.
func compileRule(t *testing.T, r policy.Rule) *policy.CompiledRule {
	t.Helper()
	env, err := policy.NewCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cr, err := policy.CompileRule(env, &r)
	if err != nil {
		t.Fatalf("compiling rule %q: %v", r.Name, err)
	}
	return cr
}
