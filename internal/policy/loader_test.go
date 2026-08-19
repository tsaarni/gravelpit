// loader_test.go tests YAML rule loading, validation, and CEL compilation.
package policy

import (
	"strings"
	"testing"
)

func TestLoaderBasic(t *testing.T) {
	yaml := `
- name: allow-reads
  action: read
  verdict: allow
  match: "true"
- name: block-hidden
  action: read
  verdict: deny
  match: 'pathMatch(path, "/home/user/.*")'
`
	l, err := NewLoader(WithVariables(map[string]string{"$HOME": "/home/user"}))
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Name != "allow-reads" {
		t.Errorf("rule 0 name = %q", rules[0].Name)
	}
	if rules[1].Name != "block-hidden" {
		t.Errorf("rule 1 name = %q", rules[1].Name)
	}
	if len(rules[0].Patterns) != 0 {
		t.Errorf("true rule should have no patterns, got %v", rules[0].Patterns)
	}
}

func TestLoaderMultiAction(t *testing.T) {
	yaml := `
- name: workspace
  action: [write, delete]
  verdict: allow
  match: 'pathMatch(path, "/home/user/work/**")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if len(rules[0].Actions) != 2 {
		t.Errorf("got %d actions, want 2", len(rules[0].Actions))
	}
}

func TestLoaderVariableExpansion(t *testing.T) {
	yaml := `
- name: test
  action: read
  verdict: deny
  match: 'pathMatch(path, "$HOME/.ssh/**")'
`
	l, err := NewLoader(WithVariables(map[string]string{"$HOME": "/home/testuser"}))
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	// The compiled match should have the expanded path.
	if !strings.Contains(rules[0].Match, "/home/testuser/.ssh/**") {
		t.Errorf("variable not expanded in match: %q", rules[0].Match)
	}
}

func TestLoaderRejectsHashComment(t *testing.T) {
	yaml := `
- name: bad-rule
  action: read
  verdict: deny
  match: 'pathMatch(path, "/home/user/.ssh/**") # block ssh'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for # in match expression")
	}
	if !strings.Contains(errs[0].Error(), "#") {
		t.Errorf("error should mention #: %v", errs[0])
	}
}

func TestLoaderRejectsMidPatternDoubleStar(t *testing.T) {
	yaml := `
- name: bad-pattern
  action: read
  verdict: deny
  match: 'pathMatch(path, "/home/user/work/**/.env")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for mid-pattern **")
	}
	if !strings.Contains(errs[0].Error(), "**") {
		t.Errorf("error should mention **: %v", errs[0])
	}
}

func TestLoaderAllowsTerminalDoubleStar(t *testing.T) {
	yaml := `
- name: ok-pattern
  action: read
  verdict: allow
  match: 'pathMatch(path, "/home/user/.cache/**")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestLoaderRejectsInvalidAction(t *testing.T) {
	yaml := `
- name: bad
  action: destroy
  verdict: allow
  match: "true"
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid action")
	}
}

func TestLoaderRejectsInvalidVerdict(t *testing.T) {
	yaml := `
- name: bad
  action: read
  verdict: maybe
  match: "true"
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid verdict")
	}
}

func TestLoaderRejectsNoName(t *testing.T) {
	yaml := `
- action: read
  verdict: allow
  match: "true"
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for missing name")
	}
}

func TestLoaderCELCompileError(t *testing.T) {
	yaml := `
- name: broken
  action: read
  verdict: deny
  match: 'this is not valid CEL at all'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid CEL")
	}
}

func TestLoaderRejectsUnanchoredPattern(t *testing.T) {
	yaml := `
- name: bad-unanchored
  action: read
  verdict: deny
  match: 'pathMatch(path, "relative/path")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for unanchored pattern")
	}
	if !strings.Contains(errs[0].Error(), "must start with") {
		t.Errorf("error should mention anchoring: %v", errs[0])
	}
}

func TestLoaderAcceptsAnchoredPatterns(t *testing.T) {
	yaml := `
- name: slash-anchored
  action: read
  verdict: allow
  match: 'pathMatch(path, "/home/user/work/**")'
- name: var-anchored
  action: read
  verdict: allow
  match: 'pathMatch(path, "$HOME/.cache/**")'
`
	l, err := NewLoader(WithVariables(map[string]string{"$HOME": "/home/user"}))
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestLoaderRejectsMixedOperators(t *testing.T) {
	yaml := `
- name: mixed-ops
  action: read
  verdict: deny
  match: 'action == "write" && pathMatch(path, "/tmp/**") || pathMatch(path, "/var/**")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) == 0 {
		t.Fatal("expected error for mixed && and || without parentheses")
	}
	if !strings.Contains(errs[0].Error(), "&&") && !strings.Contains(errs[0].Error(), "||") {
		t.Errorf("error should mention operators: %v", errs[0])
	}
}

func TestLoaderAcceptsMixedOperatorsWithParens(t *testing.T) {
	yaml := `
- name: parenthesized
  action: read
  verdict: deny
  match: '(action == "write" && pathMatch(path, "/tmp/**")) || pathMatch(path, "/var/**")'
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors for parenthesized expression: %v", errs)
	}
}

// TestLoaderAuditAndNotify checks that both fields survive YAML loading and
// that omitting them means true. They are pointers so that "unset" is
// distinguishable from "false", and a plain bool would silently default to
// false and suppress everything.
func TestLoaderAuditAndNotify(t *testing.T) {
	yaml := `
- name: defaults
  action: read
  verdict: deny
  match: 'pathMatch(path, "/a")'
- name: no-audit
  action: read
  verdict: deny
  match: 'pathMatch(path, "/b")'
  audit: false
- name: no-notify
  action: read
  verdict: deny
  match: 'pathMatch(path, "/c")'
  notify: false
- name: explicit-true
  action: read
  verdict: deny
  match: 'pathMatch(path, "/d")'
  audit: true
  notify: true
`
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}

	tests := []struct {
		name       string
		wantAudit  bool
		wantNotify bool
	}{
		{"defaults", true, true},
		{"no-audit", false, true},
		{"no-notify", true, false},
		{"explicit-true", true, true},
	}
	for i, tc := range tests {
		r := rules[i]
		if r.Name != tc.name {
			t.Fatalf("rule %d name = %q, want %q", i, r.Name, tc.name)
		}
		if got := r.ShouldAudit(); got != tc.wantAudit {
			t.Errorf("rule %q ShouldAudit() = %v, want %v", tc.name, got, tc.wantAudit)
		}
		if got := r.ShouldNotify(); got != tc.wantNotify {
			t.Errorf("rule %q ShouldNotify() = %v, want %v", tc.name, got, tc.wantNotify)
		}
	}
}

// TestNilRuleAuditAndNotify covers the default-deny case, where no rule matched
// and Decision.Rule is nil. Such a denial must still be audited and reported:
// it means the policy has a gap.
func TestNilRuleAuditAndNotify(t *testing.T) {
	var r *Rule
	if !r.ShouldAudit() {
		t.Error("nil rule ShouldAudit() = false, want true")
	}
	if !r.ShouldNotify() {
		t.Error("nil rule ShouldNotify() = false, want true")
	}
}

// Rule.Line is printed as file:line by policy eval, so it has to be the line the
// rule starts on. It used to be the rule's ordinal in the file, which pointed at
// an unrelated line for every rule after the first.
func TestLoaderRealLineNumbers(t *testing.T) {
	yaml := `# a comment line
- name: first
  action: read
  verdict: allow
  match: "true"

- name: second
  action: read
  verdict: deny
  match: 'pathMatch(path, "/etc/**")'
`
	l, err := NewLoader(WithVariables(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	rules, errs := l.LoadBytes([]byte(yaml), "test.yaml")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := map[string]int{"first": 2, "second": 7}
	for _, r := range rules {
		if got := r.Line; got != want[r.Name] {
			t.Errorf("rule %q line = %d, want %d", r.Name, got, want[r.Name])
		}
	}
}
