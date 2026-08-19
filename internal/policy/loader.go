package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

// Loader loads and compiles policy rules from YAML files.
type Loader struct {
	env    *cel.Env
	mapper func(string) string // Maps variable names to values for os.Expand.
}

// LoaderOption configures the loader.
type LoaderOption func(*Loader)

// WithVariables overrides the variable expansion map. When set, only the
// provided variables are expanded (used in tests for deterministic output).
func WithVariables(vars map[string]string) LoaderOption {
	return func(l *Loader) {
		l.mapper = func(name string) string {
			return vars["$"+name]
		}
	}
}

// NewLoader creates a policy loader with the given options.
func NewLoader(opts ...LoaderOption) (*Loader, error) {
	env, err := NewCELEnv()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}
	l := &Loader{
		env:    env,
		mapper: defaultMapper(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// LoadDir loads all *.yaml files from a directory and returns compiled rules.
func (l *Loader) LoadDir(dir string) ([]*CompiledRule, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("reading policy dir: %w", err)}
	}

	var rules []*CompiledRule
	var errs []error

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fileRules, fileErrs := l.LoadFile(path)
		rules = append(rules, fileRules...)
		errs = append(errs, fileErrs...)
	}

	return rules, errs
}

// LoadFile loads and compiles rules from a single YAML file.
func (l *Loader) LoadFile(path string) ([]*CompiledRule, []error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []error{fmt.Errorf("reading %s: %w", path, err)}
	}
	return l.LoadBytes(data, path)
}

// LoadBytes parses and compiles rules from raw YAML bytes.
//
// Rules are decoded one node at a time so each keeps the line it starts on.
// A rule location is printed as file:line and used to jump to the rule, so it
// has to be the real line, not the rule's ordinal in the file.
func (l *Loader) LoadBytes(data []byte, sourcePath string) ([]*CompiledRule, []error) {
	var nodes []yaml.Node
	if err := yaml.Unmarshal(data, &nodes); err != nil {
		return nil, []error{fmt.Errorf("parsing %s: %w", sourcePath, err)}
	}

	var compiled []*CompiledRule
	var errs []error

	for i := range nodes {
		var rule Rule
		if err := nodes[i].Decode(&rule); err != nil {
			errs = append(errs, fmt.Errorf("parsing %s: rule at position %d (line %d): %w",
				sourcePath, i+1, nodes[i].Line, err))
			continue
		}
		r, err := l.compileRule(&rule, sourcePath, i+1, nodes[i].Line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		compiled = append(compiled, r)
	}

	return compiled, errs
}

func (l *Loader) compileRule(rule *Rule, sourcePath string, position, line int) (*CompiledRule, error) {
	// Validate name.
	if rule.Name == "" {
		return nil, fmt.Errorf("%s: rule at position %d has no name", sourcePath, position)
	}

	// Validate actions.
	if len(rule.Actions) == 0 {
		return nil, fmt.Errorf("%s: rule %q: no action specified", sourcePath, rule.Name)
	}

	// Validate verdict.
	if rule.Verdict != VerdictAllow && rule.Verdict != VerdictDeny {
		return nil, fmt.Errorf("%s: rule %q: verdict must be 'allow' or 'deny', got %q", sourcePath, rule.Name, rule.Verdict)
	}

	// Expand variables in match expression and message.
	rule.Match = l.expandVars(rule.Match)

	// Rewrite startedBy("name") -> "name" in ancestors before CEL compilation.
	rule.Match = rewriteStartedBy(rule.Match)

	// Lint: reject # comments inside match expressions.
	if err := lintHashComment(rule.Match, rule.Name, sourcePath); err != nil {
		return nil, err
	}

	// Lint: reject ** not at end of pattern.
	if err := lintMidPatternDoubleStar(rule.Match, rule.Name, sourcePath); err != nil {
		return nil, err
	}

	// Lint: reject unanchored pathMatch patterns (not starting with / or $).
	if err := lintUnanchored(rule.Match, rule.Name, sourcePath); err != nil {
		return nil, err
	}

	// Lint: reject mixed && and || without parentheses.
	if err := lintMixedOperators(rule.Match, rule.Name, sourcePath); err != nil {
		return nil, err
	}

	rule.File = sourcePath
	rule.Line = line

	compiled, err := CompileRule(l.env, rule)
	if err != nil {
		return nil, err
	}

	return compiled, nil
}

func (l *Loader) expandVars(s string) string {
	return os.Expand(s, l.mapper)
}

// ExpandVars expands environment variables in a string using the same logic as
// the policy loader. Any $VAR or ${VAR} is replaced with its value from the
// environment. WORKDIR defaults to the current working directory if not set.
func ExpandVars(s string) string {
	return os.Expand(s, defaultMapper())
}

// defaultMapper returns a mapping function that resolves any environment
// variable. It adds a fallback for WORKDIR (current working directory) when
// it is not explicitly set in the environment.
func defaultMapper() func(string) string {
	return func(name string) string {
		if val, ok := os.LookupEnv(name); ok {
			return val
		}
		// Provide a default for WORKDIR since it is not a standard env var
		// but is commonly used in policy files.
		if name == "WORKDIR" {
			wd, _ := os.Getwd()
			return wd
		}
		return ""
	}
}

// lintHashComment rejects # inside a match expression. CEL uses // for
// comments (COMMENT ::= '//' ~\n* \n), but the surrounding file is YAML where #
// is the comment character. The wrong one is easy to reach for, and the failure
// is a CEL parse error with no obvious cause.
func lintHashComment(expr, ruleName, file string) error {
	// Only check inside string content (outside of quoted strings).
	inString := false
	for i := 0; i < len(expr); i++ {
		if expr[i] == '"' {
			inString = !inString
			continue
		}
		if !inString && expr[i] == '#' {
			return fmt.Errorf("%s: rule %q: '#' found in match expression (CEL uses // for comments)", file, ruleName)
		}
	}
	return nil
}

// lintMidPatternDoubleStar rejects patterns where ** appears not at the end.
func lintMidPatternDoubleStar(expr, ruleName, file string) error {
	// Extract string literals from the expression and check patterns.
	rest := expr
	for {
		q1 := strings.Index(rest, "\"")
		if q1 < 0 {
			break
		}
		rest = rest[q1+1:]
		q2 := strings.Index(rest, "\"")
		if q2 < 0 {
			break
		}
		literal := rest[:q2]
		rest = rest[q2+1:]

		// Check if ** appears somewhere that is not the end.
		idx := strings.Index(literal, "**")
		if idx < 0 {
			continue
		}
		// Valid: pattern ends with ** or **/
		after := literal[idx+2:]
		if after == "" || after == "/" {
			continue
		}
		// ** is not at the end -> reject.
		return fmt.Errorf("%s: rule %q: '**' must only appear at the end of a pattern, got %q", file, ruleName, literal)
	}
	return nil
}

// lintUnanchored rejects pathMatch patterns that do not start with '/' or '$'.
// Every pattern must start at an absolute root or a variable that expands to
// one. A pattern with no root matches anywhere while naming almost nothing, so
// its specificity score would not reflect where it applies and an unrelated
// allow rule could outrank it.
func lintUnanchored(expr, ruleName, file string) error {
	rest := expr
	for {
		idx := strings.Index(rest, "pathMatch(")
		if idx < 0 {
			break
		}
		rest = rest[idx+len("pathMatch("):]
		// Skip to the comma separating the first and second arguments.
		comma := strings.Index(rest, ",")
		if comma < 0 {
			break
		}
		after := rest[comma+1:]
		// Find the opening quote of the pattern literal.
		q1 := strings.Index(after, "\"")
		if q1 < 0 {
			break
		}
		after = after[q1+1:]
		q2 := strings.Index(after, "\"")
		if q2 < 0 {
			break
		}
		pattern := after[:q2]
		rest = after[q2+1:]
		if len(pattern) == 0 || (pattern[0] != '/' && pattern[0] != '$') {
			return fmt.Errorf("%s: rule %q: pathMatch pattern %q must start with '/' or '$' (a variable expanding to an absolute path)", file, ruleName, pattern)
		}
	}
	return nil
}

// lintMixedOperators rejects match expressions that mix && and || at the same
// parenthesis depth without grouping. CEL binds && tighter than ||, so
// `a && b || c && d` parses as `(a && b) || (c && d)`. This is easy to write
// when the intent is `a && (b || c) && d`, and nearly invisible on review.
func lintMixedOperators(expr, ruleName, file string) error {
	// Track whether && and || both appear at depth 0. If both are seen, the
	// expression has ambiguous precedence and must be parenthesized.
	depth := 0
	sawAnd := false
	sawOr := false
	inString := false

	for i := 0; i < len(expr); i++ {
		ch := expr[i]

		// Track string literals so we do not scan inside them.
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '&':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == '&' {
				sawAnd = true
				i++ // skip second &
			}
		case '|':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == '|' {
				sawOr = true
				i++ // skip second |
			}
		}

		if sawAnd && sawOr {
			return fmt.Errorf("%s: rule %q: match expression mixes '&&' and '||' at the same level without parentheses; add parentheses to make precedence explicit", file, ruleName)
		}
	}
	return nil
}

// rewriteStartedBy rewrites startedBy("name") to "name" in ancestors.
// This allows the user-facing startedBy(name) syntax while using the ancestors
// list variable that is bound in the CEL activation.
func rewriteStartedBy(expr string) string {
	const prefix = "startedBy("
	if !strings.Contains(expr, prefix) {
		return expr
	}

	var b strings.Builder
	b.Grow(len(expr))
	rest := expr

	for {
		idx := strings.Index(rest, prefix)
		if idx < 0 {
			b.WriteString(rest)
			break
		}

		// Write everything before startedBy(.
		b.WriteString(rest[:idx])
		rest = rest[idx+len(prefix):]

		// Find the matching closing paren. Expect a single string literal arg.
		q1 := strings.Index(rest, "\"")
		if q1 < 0 {
			// Not a string literal; leave it as-is.
			b.WriteString(prefix)
			continue
		}
		inner := rest[q1+1:]
		q2 := strings.Index(inner, "\"")
		if q2 < 0 {
			b.WriteString(prefix)
			continue
		}
		name := inner[:q2]
		rest = inner[q2+1:]

		// Skip optional whitespace and closing paren.
		trimmed := strings.TrimLeft(rest, " \t")
		if len(trimmed) > 0 && trimmed[0] == ')' {
			rest = trimmed[1:]
		}

		// Emit: "name" in ancestors
		fmt.Fprintf(&b, "%q in ancestors", name)
	}

	return b.String()
}
