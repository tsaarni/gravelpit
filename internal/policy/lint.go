// lint.go provides a top-level Lint function that loads, compiles, and checks
// all policy files in a directory, returning structured results.
package policy

// LintResult holds the outcome of linting a policy directory.
type LintResult struct {
	Rules   []*CompiledRule // successfully compiled rules
	Errors  []error         // compilation and lint errors
	RuleDir string          // directory that was linted
}

// Ok returns true if no errors were found.
func (r *LintResult) Ok() bool {
	return len(r.Errors) == 0
}

// Lint loads, compiles, and checks all *.yaml policy files in dir.
// It returns all successfully compiled rules and any errors encountered
// (CEL compilation failures, lint violations).
func Lint(dir string, opts ...LoaderOption) *LintResult {
	loader, err := NewLoader(opts...)
	if err != nil {
		return &LintResult{
			RuleDir: dir,
			Errors:  []error{err},
		}
	}

	rules, errs := loader.LoadDir(dir)
	return &LintResult{
		Rules:   rules,
		Errors:  errs,
		RuleDir: dir,
	}
}
