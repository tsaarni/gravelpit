// builtin_test.go tests that built-in protection rules compile successfully.
package policy

import "testing"

func TestBuiltinRules(t *testing.T) {
	rules, err := BuiltinRules()
	if err != nil {
		t.Fatalf("BuiltinRules() error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 built-in rules, got %d", len(rules))
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	if !names["protect-gravelpit-files"] {
		t.Error("protect-gravelpit-files rule missing")
	}
	if !names["protect-gravelpit-socket"] {
		t.Error("protect-gravelpit-socket rule missing")
	}
}
