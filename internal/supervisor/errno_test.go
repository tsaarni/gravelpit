// errno_test.go checks that the errno written to an audit record is the one the
// process actually receives.
package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/policy"
)

func TestRecordErrnoMatchesWhatTheProcessGets(t *testing.T) {
	tests := []struct {
		name      string
		action    policy.Action
		ruleErrno string
		want      string
	}{
		// Default deny leaves the rule errno empty, but the syscall still fails.
		{"default deny on read", policy.ActionRead, "", "EACCES"},
		{"default deny on connect", policy.ActionConnect, "", "ECONNREFUSED"},
		{"rule errno", policy.ActionRead, "ENOENT", "ENOENT"},
		{"rule errno lowercase", policy.ActionRead, "erofs", "EROFS"},
		// An unknown name cannot be returned, so the record must not claim it.
		{"unknown rule errno", policy.ActionRead, "ENOTAREALERRNO", "EACCES"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := recordErrno(tc.action, tc.ruleErrno)
			if got != tc.want {
				t.Errorf("recordErrno(%s, %q) = %q, want %q", tc.action, tc.ruleErrno, got, tc.want)
			}
			// The recorded name must resolve to the errno actually returned.
			if lookupErrno(got) != denyErrno(tc.action, tc.ruleErrno) {
				t.Errorf("recorded %q resolves to %v, but the process gets %v",
					got, lookupErrno(got), denyErrno(tc.action, tc.ruleErrno))
			}
		})
	}
}

func TestDefaultErrnoName(t *testing.T) {
	if got := denyErrno(policy.ActionConnect, ""); got != unix.ECONNREFUSED {
		t.Errorf("connect default = %v, want ECONNREFUSED", got)
	}
	if got := denyErrno(policy.ActionWrite, ""); got != unix.EACCES {
		t.Errorf("write default = %v, want EACCES", got)
	}
}
