package policy

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
)

// CompiledRule is a rule with its CEL program ready to execute.
type CompiledRule struct {
	Rule
	Program  cel.Program // nil for fast-path rules
	Patterns []string    // All pathMatch pattern literals extracted from the expression
	Prefixes []string    // Literal prefix of each pattern (up to first wildcard), for fast rejection
	FastPath bool        // True if evaluable without CEL (pure pathMatch || chain)
}

// Engine evaluates events against a compiled rule set.
//
// Evaluation model:
//   - Every rule for the action is evaluated. Of the rules that match, the one
//     whose pattern names the most of the path decides ("most-specific-wins").
//   - Specificity is the count of literal characters in the matching pattern
//     (everything except wildcards, after variable expansion).
//   - A tie between allow and deny goes to deny.
//   - If no rule matches, the answer is always deny (not configurable).
//   - Rules are indexed by action so a notification is only evaluated against
//     rules that apply to it.
type Engine struct {
	rules              map[Action][]*CompiledRule
	unconditionalAllow map[Action]bool // actions with only match:"true" allow rules, no deny

	// hasContextRules is false for the common policy where no rule reads
	// process, ancestors or sandbox. It keeps the cacheability check on the
	// syscall path down to one bool test in that case.
	hasContextRules bool
	// contextRules holds, per action, the rules that read process context.
	// An action absent from the map is fully cacheable.
	contextRules map[Action][]contextRule
}

// contextRule is a rule whose verdict depends on more than the action and the
// target, so a decision it can influence must not be stored in the path-keyed
// cache. Two kinds of dependency exist:
//
//   - the calling process (process, ancestors, sandbox), which has to be read
//     from /proc and the process table before evaluation
//   - the syscall (syscall.name, syscall.number), which is already decoded and
//     costs nothing to supply, but still breaks the cache key: open, openat and
//     openat2 all produce action "read" for the same path, as do chmod and
//     fchmodat for "metadata". A cached verdict keyed on (action, target) would
//     be served to a different syscall than the one it was computed for.
//
// gate holds pathMatch patterns that the target has to satisfy before the rule
// can match at all, taken from a top-level && conjunct of the match expression.
// When the target satisfies none of them the rule is provably false for this
// target, its dependency cannot affect the outcome, and the decision stays
// cacheable. A rule with no provable gate (gate == nil) can match any target and
// makes every decision for its actions uncacheable.
type contextRule struct {
	gate     []string
	prefixes []string
	// needsProcess is false for a rule that only reads the syscall. Such a rule
	// bypasses the cache but does not make the handler read /proc.
	needsProcess bool
}

// NewEngine creates an engine from a set of compiled rules.
func NewEngine(rules []*CompiledRule) *Engine {
	e := &Engine{
		rules: make(map[Action][]*CompiledRule),
	}
	for _, r := range rules {
		for _, a := range r.Actions {
			e.rules[a] = append(e.rules[a], r)
		}
	}
	e.contextRules = computeContextRules(e.rules)
	e.hasContextRules = len(e.contextRules) > 0
	e.unconditionalAllow = computeUnconditionalAllow(e.rules)
	return e
}

// CacheableTarget reports whether the decision for (action, target) is a
// function of the target alone, so it can be stored in the decision cache.
//
// Cacheability is decided per action and per target rather than for the whole
// policy: rules are indexed by action, so a process-dependent exec rule cannot
// change a read decision, and a process-dependent rule gated on
// "$HOME/.ssh/id_*" cannot change the decision for any other path. Without this
// a single rule such as
//
//	process.exe == "/usr/bin/ssh" && pathMatch(path, "$HOME/.ssh/id_*")
//
// would disable the cache for every syscall, measured at 25-36% on
// syscall-heavy workloads.
//
// The target is the same string used to build the cache key. A decoded event
// sets either Path or Socket/Host, never both, so one target string is enough
// to test every gate.
func (e *Engine) CacheableTarget(action Action, target string) bool {
	return !e.contextMatters(action, target, false)
}

// NeedsProcessContext reports whether the handler has to read process identity
// before evaluating this target. Narrower than CacheableTarget: a rule matching
// only on syscall.name bypasses the cache but needs nothing from /proc.
func (e *Engine) NeedsProcessContext(action Action, target string) bool {
	return e.contextMatters(action, target, true)
}

// contextMatters reports whether any rule for the action that reads context
// beyond the action and target can match the given target. When processOnly is
// set, rules that read only the syscall are ignored.
func (e *Engine) contextMatters(action Action, target string, processOnly bool) bool {
	if !e.hasContextRules {
		return false
	}
	for _, cr := range e.contextRules[action] {
		if processOnly && !cr.needsProcess {
			continue
		}
		if cr.gate == nil {
			return true
		}
		for i, pattern := range cr.gate {
			if cr.prefixes[i] != "" && !strings.HasPrefix(target, cr.prefixes[i]) {
				continue
			}
			if ok, _ := PathMatch(pattern, target); ok {
				return true
			}
		}
	}
	return false
}

// IsUnconditionalAllow returns true if the given action has only unconditional
// allow rules (match:"true") and no deny rules. Such actions can be allowed
// immediately without policy evaluation.
func (e *Engine) IsUnconditionalAllow(action Action) bool {
	return e.unconditionalAllow[action]
}

// UnconditionalAllowRule returns the name of the first rule for an
// unconditionally allowed action. Returns "" if the action is not unconditional.
func (e *Engine) UnconditionalAllowRule(action Action) string {
	if !e.unconditionalAllow[action] {
		return ""
	}
	if rules := e.rules[action]; len(rules) > 0 {
		return rules[0].Name
	}
	return ""
}

// computeContextRules indexes the rules that read context beyond the action and
// target, per action, with the path gate that has to hold before each one can
// match. Actions with no such rule are left out of the map so they cost nothing
// to check.
func computeContextRules(rules map[Action][]*CompiledRule) map[Action][]contextRule {
	var result map[Action][]contextRule
	for action, actionRules := range rules {
		for _, r := range actionRules {
			refs := contextRefs(r.Match)
			if len(refs) == 0 {
				continue
			}
			needsProcess := false
			for _, ref := range refs {
				if !strings.HasPrefix(ref, "syscall") {
					needsProcess = true
					break
				}
			}
			gate := requiredPatterns(r.Match)
			if result == nil {
				result = make(map[Action][]contextRule)
			}
			result[action] = append(result[action], contextRule{
				gate:         gate,
				prefixes:     patternPrefixes(gate),
				needsProcess: needsProcess,
			})
		}
	}
	return result
}

// requiredPatterns returns pathMatch patterns that the target must match for
// expr to have any chance of evaluating true, or nil when no such requirement
// can be proven.
//
// Only one shape is accepted: a top-level && conjunct that is itself a pure
// pathMatch chain, as in
//
//	process.exe == "/usr/bin/ssh" && pathMatch(path, "$HOME/.ssh/id_*")
//
// where failing every pattern makes the whole expression false. A pattern
// reached through || is not a requirement — in `process.exe == "x" ||
// pathMatch(path, P)` the rule still matches on process.exe alone — so those
// expressions return nil and stay uncacheable. Guessing wrong in this direction
// would cache a decision that depends on which process asked, so the analysis
// refuses anything it cannot prove.
func requiredPatterns(expr string) []string {
	for _, conjunct := range splitOnAnd(stripWhitespace(expr)) {
		conjunct = stripOuterParens(conjunct)
		if !isFastPathExpr(conjunct) {
			continue
		}
		if patterns := extractPatterns(conjunct); len(patterns) > 0 {
			return patterns
		}
	}
	return nil
}

// splitOnAnd splits an expression on top-level && operators, respecting
// parentheses and string literals.
func splitOnAnd(s string) []string {
	var parts []string
	depth := 0
	start := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inStr = !inStr
		case '(':
			if !inStr {
				depth++
			}
		case ')':
			if !inStr {
				depth--
			}
		case '&':
			if !inStr && depth == 0 && i+1 < len(s) && s[i+1] == '&' {
				parts = append(parts, s[start:i])
				i++ // skip second &
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// stripOuterParens removes parentheses that wrap the whole expression. It only
// strips when the opening paren is closed by the final character, so "(a)||(b)"
// is left alone while "(a||b)" is unwrapped.
func stripOuterParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && outerParenSpansAll(s) {
		s = s[1 : len(s)-1]
	}
	return s
}

// outerParenSpansAll reports whether the paren at index 0 is closed by the last
// character of s.
func outerParenSpansAll(s string) bool {
	depth := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inStr = !inStr
		case '(':
			if !inStr {
				depth++
			}
		case ')':
			if !inStr {
				depth--
				if depth == 0 {
					return i == len(s)-1
				}
			}
		}
	}
	return false
}

// computeUnconditionalAllow identifies actions where all rules are unconditional
// allows (match is "true" or empty) with no deny rules. For these actions the
// handler can skip decode, resolve, and evaluation entirely.
func computeUnconditionalAllow(rules map[Action][]*CompiledRule) map[Action]bool {
	result := make(map[Action]bool)
	for action, actionRules := range rules {
		if len(actionRules) == 0 {
			continue
		}
		unconditional := true
		for _, r := range actionRules {
			if r.Verdict == VerdictDeny {
				unconditional = false
				break
			}
			if r.Match != "" && r.Match != "true" {
				unconditional = false
				break
			}
		}
		if unconditional {
			result[action] = true
		}
	}
	return result
}

// contextRefs returns the variables an expression references that make the
// verdict depend on more than the action and the target: "process.exe",
// "sandbox.workdir", "ancestors", "syscall.name". Duplicates are removed, order
// follows first appearance.
//
// A bare "process", "sandbox" or "syscall" with no field selector is reported
// as-is, since the whole map is then in play.
func contextRefs(expr string) []string {
	var refs []string
	add := func(name string) {
		for _, existing := range refs {
			if existing == name {
				return
			}
		}
		refs = append(refs, name)
	}

	// Identifiers are matched outside string literals only, so a pattern such as
	// "/proc/self/..." or a message mentioning "sandbox" is not a reference.
	inString := false
	for i := 0; i < len(expr); i++ {
		if expr[i] == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		for _, keyword := range []string{"process", "ancestors", "sandbox", "syscall"} {
			if i+len(keyword) > len(expr) || expr[i:i+len(keyword)] != keyword {
				continue
			}
			// Reject a match that is part of a longer identifier.
			if i > 0 && isIdentChar(expr[i-1]) {
				continue
			}
			end := i + len(keyword)
			if end < len(expr) && isIdentChar(expr[end]) {
				continue
			}
			if end < len(expr) && expr[end] == '.' {
				field := end + 1
				for field < len(expr) && isIdentChar(expr[field]) {
					field++
				}
				if field > end+1 {
					add(expr[i:field])
					i = field - 1
					break
				}
			}
			add(keyword)
			i = end - 1
			break
		}
	}
	return refs
}

// UnsuppliedContext returns the context variables a rule reads that are empty in
// the event. It answers "was this rule even testable with the input given",
// which is what separates a rule that does not apply from one that could not be
// evaluated.
func UnsuppliedContext(expr string, ev *Event) []string {
	var missing []string
	for _, ref := range contextRefs(expr) {
		if contextValueEmpty(ref, ev) {
			missing = append(missing, ref)
		}
	}
	return missing
}

// contextValueEmpty reports whether a context reference has no value in the
// event. Unknown references are treated as supplied: a typo is a compile error,
// not something to report as missing input.
func contextValueEmpty(ref string, ev *Event) bool {
	switch ref {
	case "process":
		return ev.Process.Exe == "" && ev.Process.Comm == "" && ev.Process.Cwd == "" && len(ev.Process.Cmdline) == 0
	case "process.pid":
		return ev.Process.PID == 0
	case "process.tgid":
		return ev.Process.TGID == 0
	case "process.ppid":
		return ev.Process.PPID == 0
	case "process.exe":
		return ev.Process.Exe == ""
	case "process.comm":
		return ev.Process.Comm == ""
	case "process.cwd":
		return ev.Process.Cwd == ""
	case "process.cmdline":
		return len(ev.Process.Cmdline) == 0
	case "ancestors":
		return len(ev.Ancestors) == 0
	case "sandbox":
		return ev.Sandbox == SandboxInfo{}
	case "sandbox.id":
		return ev.Sandbox.ID == ""
	case "sandbox.command":
		return ev.Sandbox.Command == ""
	case "sandbox.workdir":
		return ev.Sandbox.Workdir == ""
	case "syscall":
		return ev.Syscall == SyscallInfo{}
	case "syscall.name":
		return ev.Syscall.Name == ""
	case "syscall.number":
		return ev.Syscall.Number == 0
	default:
		return false
	}
}

// isIdentChar returns true if c can be part of a CEL identifier.
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// Evaluate runs the event against all matching rules and returns the decision.
// The most specific matching rule wins. Ties go to deny.
func (e *Engine) Evaluate(ev *Event) Decision {
	candidates := e.rules[ev.Action]
	if len(candidates) == 0 {
		return Decision{Verdict: VerdictDeny}
	}

	var best *CompiledRule
	var bestScore int

	// Lazily built CEL activation — only if a non-fast-path rule exists.
	var act *eventActivation

	for _, r := range candidates {
		var matched bool
		var score int

		if r.FastPath {
			matched, score = evalFastPath(r, ev)
		} else {
			if act == nil {
				act = newEventActivation(ev)
			}
			matched, score = evalCEL(r, ev, act)
		}

		if !matched {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && r.Verdict == VerdictDeny) {
			best = r
			bestScore = score
		}
	}

	if best == nil {
		return Decision{Verdict: VerdictDeny}
	}

	msg := interpolateMessage(best.Message, ev)
	errno := best.Errno
	if errno == "" && best.Verdict == VerdictDeny {
		errno = "EACCES"
	}

	return Decision{
		Verdict: best.Verdict,
		Rule:    &best.Rule,
		Score:   bestScore,
		Message: msg,
		Errno:   errno,
	}
}

// EvaluateWithDetails returns the decision plus all rule evaluations for diagnostics.
func (e *Engine) EvaluateWithDetails(ev *Event) (Decision, []RuleMatch) {
	candidates := e.rules[ev.Action]
	if len(candidates) == 0 {
		return Decision{Verdict: VerdictDeny}, nil
	}

	var best *CompiledRule
	var bestScore int
	var matches []RuleMatch
	var act *eventActivation

	for _, r := range candidates {
		var matched bool
		var score int

		if r.FastPath {
			matched, score = evalFastPath(r, ev)
		} else {
			if act == nil {
				act = newEventActivation(ev)
			}
			matched, score = evalCEL(r, ev, act)
		}

		matches = append(matches, RuleMatch{
			Rule:    &r.Rule,
			Matched: matched,
			Score:   score,
		})

		if !matched {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && r.Verdict == VerdictDeny) {
			best = r
			bestScore = score
		}
	}

	if best == nil {
		return Decision{Verdict: VerdictDeny}, matches
	}

	msg := interpolateMessage(best.Message, ev)
	errno := best.Errno
	if errno == "" && best.Verdict == VerdictDeny {
		errno = "EACCES"
	}

	return Decision{
		Verdict: best.Verdict,
		Rule:    &best.Rule,
		Score:   bestScore,
		Message: msg,
		Errno:   errno,
	}, matches
}

// evalFastPath evaluates a pure-pathMatch rule without CEL.
// Returns (matched, maxScore).
func evalFastPath(r *CompiledRule, ev *Event) (bool, int) {
	maxScore := 0
	matched := false
	target := ev.Path
	if target == "" {
		target = ev.Socket
	}
	if target == "" {
		return false, 0
	}
	for i, pattern := range r.Patterns {
		if r.Prefixes[i] != "" && !strings.HasPrefix(target, r.Prefixes[i]) {
			continue
		}
		if ok, score := PathMatch(pattern, target); ok {
			matched = true
			if score > maxScore {
				maxScore = score
			}
		}
	}
	return matched, maxScore
}

// evalCEL evaluates a rule using the CEL interpreter.
// After the expression evaluates to true, re-scans patterns to find the score.
func evalCEL(r *CompiledRule, ev *Event, act *eventActivation) (bool, int) {
	out, _, err := r.Program.Eval(act)
	if err != nil {
		return false, 0
	}
	if out.Type() != types.BoolType || !out.Value().(bool) {
		return false, 0
	}
	// Rule matched. Compute score from patterns that actually match.
	score := ruleScore(r, ev)
	return true, score
}

// ruleScore finds the highest-scoring pattern that matches the event.
func ruleScore(r *CompiledRule, ev *Event) int {
	maxScore := 0
	if ev.Path != "" {
		for i, pattern := range r.Patterns {
			if r.Prefixes[i] != "" && !strings.HasPrefix(ev.Path, r.Prefixes[i]) {
				continue
			}
			if _, score := PathMatch(pattern, ev.Path); score > maxScore {
				maxScore = score
			}
		}
	}
	if ev.Socket != "" {
		for i, pattern := range r.Patterns {
			if r.Prefixes[i] != "" && !strings.HasPrefix(ev.Socket, r.Prefixes[i]) {
				continue
			}
			if _, score := PathMatch(pattern, ev.Socket); score > maxScore {
				maxScore = score
			}
		}
	}
	return maxScore
}

// eventActivation implements interpreter.Activation without map allocation.
// It resolves variable names directly from struct fields.
type eventActivation struct {
	ev         *Event
	processMap map[string]any // lazily built
	sandboxMap map[string]any // lazily built
	syscallMap map[string]any // lazily built
}

func newEventActivation(ev *Event) *eventActivation {
	return &eventActivation{ev: ev}
}

// Compile-time check that eventActivation implements interpreter.Activation.
var _ interpreter.Activation = (*eventActivation)(nil)

func (a *eventActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "path":
		return a.ev.Path, true
	case "requestedPath":
		return a.ev.RequestedPath, true
	case "action":
		return string(a.ev.Action), true
	case "socket":
		return a.ev.Socket, true
	case "host":
		return a.ev.Host, true
	case "port":
		return a.ev.Port, true
	case "family":
		return a.ev.Family, true
	case "process":
		if a.processMap == nil {
			a.processMap = map[string]any{
				"pid":     a.ev.Process.PID,
				"tgid":    a.ev.Process.TGID,
				"ppid":    a.ev.Process.PPID,
				"exe":     a.ev.Process.Exe,
				"comm":    a.ev.Process.Comm,
				"cmdline": a.ev.Process.Cmdline,
				"cwd":     a.ev.Process.Cwd,
			}
		}
		return a.processMap, true
	case "sandbox":
		if a.sandboxMap == nil {
			a.sandboxMap = map[string]any{
				"id":      a.ev.Sandbox.ID,
				"command": a.ev.Sandbox.Command,
				"workdir": a.ev.Sandbox.Workdir,
			}
		}
		return a.sandboxMap, true
	case "syscall":
		if a.syscallMap == nil {
			a.syscallMap = map[string]any{
				"name":   a.ev.Syscall.Name,
				"number": a.ev.Syscall.Number,
			}
		}
		return a.syscallMap, true
	case "ancestors":
		// Return a copy as a []any so CEL's type system treats it as list(string).
		list := make([]ref.Val, len(a.ev.Ancestors))
		for i, s := range a.ev.Ancestors {
			list[i] = types.String(s)
		}
		return types.DefaultTypeAdapter.NativeToValue(list), true
	default:
		return nil, false
	}
}

func (a *eventActivation) Parent() interpreter.Activation { return nil }

func interpolateMessage(msg string, ev *Event) string {
	if msg == "" {
		return ""
	}
	msg = strings.ReplaceAll(msg, "${path}", ev.Path)
	msg = strings.ReplaceAll(msg, "${requestedPath}", ev.RequestedPath)
	return msg
}

// NewCELEnv creates the shared CEL environment for compiling rule expressions.
func NewCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("path", cel.StringType),
		cel.Variable("requestedPath", cel.StringType),
		cel.Variable("action", cel.StringType),
		cel.Variable("socket", cel.StringType),
		cel.Variable("host", cel.StringType),
		cel.Variable("port", cel.IntType),
		cel.Variable("family", cel.StringType),
		cel.Variable("process", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("sandbox", cel.MapType(cel.StringType, cel.DynType)),
		// syscall.name and syscall.number identify the exact syscall. Several
		// syscalls map to one action (open, openat and openat2 are all "read"),
		// so a rule reading this bypasses the decision cache for the targets it
		// can match: the cache key cannot tell them apart.
		cel.Variable("syscall", cel.MapType(cel.StringType, cel.DynType)),
		// ancestors holds exe basenames of ancestor processes; used by startedBy().
		cel.Variable("ancestors", cel.ListType(cel.StringType)),
		cel.Function("pathMatch",
			cel.Overload("pathMatch_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(celPathMatch),
			),
		),
	)
}

// celPathMatch implements pathMatch(path, pattern) for CEL. Returns false for
// input that does not apply (empty string, type mismatch) rather than raising an
// error. This is required because a runtime error in CEL means deny, and that
// deny would apply to a connection an unrelated rule was about to allow.
func celPathMatch(lhs, rhs ref.Val) ref.Val {
	path, ok1 := lhs.Value().(string)
	pattern, ok2 := rhs.Value().(string)
	if !ok1 || !ok2 {
		return types.Bool(false)
	}
	matched, _ := PathMatch(pattern, path)
	return types.Bool(matched)
}

// CompileRule compiles a rule's match expression into a CEL program.
func CompileRule(env *cel.Env, r *Rule) (*CompiledRule, error) {
	expr := r.Match
	patterns := extractPatterns(expr)

	// Check if this is a fast-path rule (pure pathMatch || chain on path or socket).
	if isFastPathExpr(expr) && len(patterns) > 0 {
		return &CompiledRule{
			Rule:     *r,
			Program:  nil,
			Patterns: patterns,
			Prefixes: patternPrefixes(patterns),
			FastPath: true,
		}, nil
	}

	// "true" or empty -> always matches, score 0.
	if expr == "" || expr == "true" {
		ast, iss := env.Compile("true")
		if iss.Err() != nil {
			return nil, fmt.Errorf("compiling true: %w", iss.Err())
		}
		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("programming true: %w", err)
		}
		return &CompiledRule{Rule: *r, Program: prg, FastPath: false}, nil
	}

	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Name, iss.Err())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Name, err)
	}

	return &CompiledRule{Rule: *r, Program: prg, Patterns: patterns, Prefixes: patternPrefixes(patterns), FastPath: false}, nil
}

// isFastPathExpr checks if an expression is a pure pathMatch chain that can be
// evaluated without CEL. The expression must be of the form:
//
//	pathMatch(path, "...") || pathMatch(path, "...") || ...
//
// or a single pathMatch(path, "...") call.
// It may also use `socket` instead of `path`.
func isFastPathExpr(expr string) bool {
	if expr == "" || expr == "true" {
		return false
	}
	// Strip all whitespace for simpler parsing.
	s := stripWhitespace(expr)

	// Split on ||
	parts := splitOnOr(s)
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !isSimplePathMatch(part) {
			return false
		}
	}
	return true
}

// isSimplePathMatch checks if a string is exactly pathMatch(path,"...") or pathMatch(socket,"...").
func isSimplePathMatch(s string) bool {
	if !strings.HasPrefix(s, "pathMatch(") {
		return false
	}
	if !strings.HasSuffix(s, ")") {
		return false
	}
	inner := s[len("pathMatch(") : len(s)-1]
	// Should be: path,"..." or socket,"..."
	comma := strings.Index(inner, ",")
	if comma < 0 {
		return false
	}
	field := strings.TrimSpace(inner[:comma])
	if field != "path" && field != "socket" {
		return false
	}
	pattern := strings.TrimSpace(inner[comma+1:])
	// Pattern must be a string literal.
	if len(pattern) < 2 || pattern[0] != '"' || pattern[len(pattern)-1] != '"' {
		return false
	}
	// No escape sequences or interpolation.
	inner2 := pattern[1 : len(pattern)-1]
	if strings.ContainsAny(inner2, "\\\"") {
		return false
	}
	return true
}

// splitOnOr splits an expression on top-level || operators, respecting parentheses.
func splitOnOr(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 && i+1 < len(s) && s[i+1] == '|' {
				parts = append(parts, s[start:i])
				i++ // skip second |
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func stripWhitespace(s string) string {
	// Only strip whitespace outside of quoted strings.
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			inStr = !inStr
			b.WriteByte(s[i])
		} else if inStr || (s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r') {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// patternPrefix returns the literal prefix of a glob pattern, up to but not
// including the first wildcard character (*, ?). Used for fast rejection before
// running the full glob match. For patterns ending in /**, the trailing / is
// stripped so that the directory itself (matched by dir/**) passes the prefix check.
func patternPrefix(pattern string) string {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '*' || pattern[i] == '?' {
			// Trim trailing slash so "dir/**" produces prefix "dir" not "dir/".
			// This is needed because dir/** matches dir itself.
			prefix := pattern[:i]
			if len(prefix) > 1 && prefix[len(prefix)-1] == '/' {
				prefix = prefix[:len(prefix)-1]
			}
			return prefix
		}
	}
	return pattern
}

// patternPrefixes extracts the literal prefix for each pattern.
func patternPrefixes(patterns []string) []string {
	prefixes := make([]string, len(patterns))
	for i, p := range patterns {
		prefixes[i] = patternPrefix(p)
	}
	return prefixes
}

// extractPatterns finds all string literals used as the second argument to pathMatch().
func extractPatterns(expr string) []string {
	var patterns []string
	rest := expr
	for {
		idx := strings.Index(rest, "pathMatch(")
		if idx < 0 {
			break
		}
		rest = rest[idx+len("pathMatch("):]
		comma := strings.Index(rest, ",")
		if comma < 0 {
			break
		}
		after := rest[comma+1:]
		q1 := strings.Index(after, "\"")
		if q1 < 0 {
			break
		}
		after = after[q1+1:]
		q2 := strings.Index(after, "\"")
		if q2 < 0 {
			break
		}
		patterns = append(patterns, after[:q2])
		rest = after[q2+1:]
	}

	// Also extract exact string comparisons: socket == "..." or path == "..."
	for _, field := range []string{"socket", "path"} {
		search := expr
		for {
			pattern := field + ` == "`
			idx := strings.Index(search, pattern)
			if idx < 0 {
				break
			}
			after := search[idx+len(pattern):]
			q := strings.Index(after, "\"")
			if q < 0 {
				break
			}
			patterns = append(patterns, after[:q])
			search = after[q+1:]
		}
	}

	return patterns
}
