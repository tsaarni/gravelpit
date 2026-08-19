// suppress_test.go verifies that the audit and notify rule fields suppress the
// audit record and the process-visible message independently of each other.
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

// defaultDenyFallback stands in for config.DefaultDenyMessage. The real text
// tells the reader to stop and ask the user, which is the outcome notify:false
// exists to prevent, so the test asserts this string never reaches the process.
const defaultDenyFallback = "DEFAULT-DENY-FALLBACK"

// suppressProbePaths are the files the probe tries to read, one per combination
// of audit and notify. Names are relative to the home dir.
var suppressProbePaths = []string{
	"loud",        // audit + notify default (true)
	"quiet-nomsg", // notify:false, rule has no message -> fallback must be suppressed too
	"noaudit",     // audit:false, notify default
	"silent",      // both false
}

// probeSuppress reads each file once. Every read is denied by policy; what
// differs is whether the denial is recorded and whether the process is told.
func probeSuppress(homeDir, workDir string) {
	for _, name := range suppressProbePaths {
		tryOpen(filepath.Join(homeDir, name), unix.O_RDONLY)
	}
}

func TestAuditAndNotifySuppression(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	// The files must exist so the denial is the only reason the open fails.
	for _, name := range suppressProbePaths {
		writeFile(t, filepath.Join(homeDir, name), "content")
	}

	res := runSandbox(t, sandboxOpts{
		rules:              buildSuppressRules(t, homeDir),
		probeSet:           "suppress",
		defaultDenyMessage: defaultDenyFallback,
		homeDir:            homeDir,
		workDir:            workDir,
	})

	t.Logf("Collected %d records:", len(res.records))
	for _, r := range res.records {
		t.Logf("  %-5s %-40s delivered=%v", r.Verdict, r.Path, r.MessageDelivered)
	}
	t.Logf("Probe stderr:\n%s", res.stderr)

	tests := []struct {
		name          string
		file          string
		message       string // rule message, "" when the rule has none
		wantRecord    bool
		wantDelivered bool
	}{
		{"defaults audit and notify", "loud", "LOUD-MSG", true, true},
		{"notify false suppresses fallback", "quiet-nomsg", "", true, false},
		{"audit false keeps the message", "noaudit", "NOAUDIT-MSG", false, true},
		{"both false", "silent", "SILENT-MSG", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(homeDir, tc.file)

			rec := findRecord(res.records, path)
			if tc.wantRecord && rec == nil {
				t.Errorf("no audit record for %s, want one", tc.file)
			}
			if !tc.wantRecord && rec != nil {
				t.Errorf("audit record written for %s despite audit:false", tc.file)
			}

			// The message the process would have seen: the rule's own text, or
			// the fallback when the rule has none.
			want := tc.message
			if want == "" {
				want = defaultDenyFallback
			}
			got := strings.Contains(res.stderr, want)
			if got != tc.wantDelivered {
				t.Errorf("stderr contains %q = %v, want %v", want, got, tc.wantDelivered)
			}

			// MessageDelivered must agree with what actually reached stderr,
			// otherwise the audit log misreports whether the process was told.
			if rec != nil && rec.MessageDelivered != tc.wantDelivered {
				t.Errorf("record MessageDelivered = %v, want %v", rec.MessageDelivered, tc.wantDelivered)
			}
		})
	}

	// Suppression must not hide denials from the counters, which are the one
	// view meant for noticing that denials are happening at all.
	summary := res.stats.Summary()
	if got := summary.ActionDenies["read"]; got != int64(len(suppressProbePaths)) {
		t.Errorf("stats recorded %d read denies, want %d: suppression must not affect counters",
			got, len(suppressProbePaths))
	}
}

// findRecord returns the audit record for an exact path, or nil.
func findRecord(records []*schema.AuditRecord, path string) *schema.AuditRecord {
	for _, r := range records {
		if r.Path == path {
			return r
		}
	}
	return nil
}

// buildSuppressRules returns one deny rule per audit/notify combination. Each
// pattern names a distinct file so the rules cannot overlap.
func buildSuppressRules(t *testing.T, homeDir string) []*policy.CompiledRule {
	t.Helper()

	falseVal := false
	trueVal := true

	rawRules := []policy.Rule{
		{
			Name:    "allow-reads",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictAllow,
			Match:   "true",
		},
		{
			Name:    "deny-loud",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictDeny,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/loud")`, homeDir),
			Message: "LOUD-MSG",
		},
		{
			Name:    "deny-quiet-nomsg",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictDeny,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/quiet-nomsg")`, homeDir),
			Notify:  &falseVal,
		},
		{
			Name:    "deny-noaudit",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictDeny,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/noaudit")`, homeDir),
			Message: "NOAUDIT-MSG",
			Audit:   &falseVal,
			Notify:  &trueVal, // explicit true must behave like unset
		},
		{
			Name:    "deny-silent",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictDeny,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/silent")`, homeDir),
			Message: "SILENT-MSG",
			Audit:   &falseVal,
			Notify:  &falseVal,
		},
	}

	env, err := policy.NewCELEnv()
	if err != nil {
		t.Fatal(err)
	}

	var compiled []*policy.CompiledRule
	for i := range rawRules {
		cr, err := policy.CompileRule(env, &rawRules[i])
		if err != nil {
			t.Fatalf("compiling rule %q: %v", rawRules[i].Name, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}
