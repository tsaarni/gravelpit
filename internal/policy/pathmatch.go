// pathmatch.go implements glob matching with specificity scoring for policy rules.
package policy

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// PathMatch checks whether path matches the glob pattern and returns the
// specificity score (number of literal characters in the pattern).
//
// Semantics:
//   - * matches zero or more characters within one path segment (does not cross /)
//   - ** matches zero or more complete path segments
//   - dir/** matches dir itself AND everything below it
//   - ? matches exactly one character, not /
//   - * matches a leading dot (unlike shell globbing)
//   - Matching is anchored (whole path) and case-sensitive
//   - Trailing slashes are normalised away before matching
//
// These matter for security:
//   - * matching a leading dot ensures $HOME/* covers $HOME/.ssh. Without this,
//     rules would silently skip exactly the files most likely to hold secrets.
//   - dir/** including dir itself prevents a footgun where the directory is
//     denied while its contents are allowed (breaks ls, opendir, build caches).
//   - Anchored matching means $HOME/.ssh does not match $HOME/.ssh_backup.
//
// Go's filepath.Match does not support ** and is not usable here.
func PathMatch(pattern, path string) (matched bool, score int) {
	pattern = strings.TrimRight(pattern, "/")
	path = strings.TrimRight(path, "/")

	matched = doublestar.MatchUnvalidated(pattern, path)
	if matched {
		score = PatternScore(pattern)
	}
	return matched, score
}

// ValidatePattern checks whether a pattern is syntactically valid.
// Call this at load time so MatchUnvalidated can be used on the hot path.
func ValidatePattern(pattern string) bool {
	return doublestar.ValidatePattern(strings.TrimRight(pattern, "/"))
}

// PatternScore returns the specificity score of a pattern: the count of literal
// characters (everything except `*` and `?` wildcards).
//
// This is computed once at load time and stored on the compiled rule.
func PatternScore(pattern string) int {
	pattern = strings.TrimRight(pattern, "/")
	n := 0
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' && pattern[i] != '?' {
			n++
		}
	}
	return n
}
