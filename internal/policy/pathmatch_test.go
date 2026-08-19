// pathmatch_test.go tests glob pattern matching and specificity scoring.
package policy

import "testing"

func TestPathMatch(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		path      string
		wantMatch bool
		wantScore int
	}{
		// Basic literal matching
		{"exact match", "/etc/passwd", "/etc/passwd", true, 11},
		{"exact no match", "/etc/passwd", "/etc/shadow", false, 0},

		// Single star - does not cross /
		{"star matches segment", "/home/*/file", "/home/user/file", true, 11},
		{"star does not cross slash", "/home/*/file", "/home/a/b/file", false, 0},
		{"star matches empty", "/home/*/file", "/home//file", true, 11},
		{"star matches dotfile", "/home/*", "/home/.ssh", true, 6},
		{"star at end", "/tmp/*", "/tmp/foo", true, 5},
		{"star at end no subdir", "/tmp/*", "/tmp/foo/bar", false, 0},

		// Double star at end - matches zero or more segments below
		{"dstar at end matches subpath", "/home/**", "/home/a/b/c", true, 6},
		{"dstar at end matches one level", "/home/**", "/home/file", true, 6},

		// dir/** includes dir itself
		{"dir/** matches dir itself", "/home/.cache/**", "/home/.cache", true, 13},
		{"dir/** matches file under dir", "/home/.cache/**", "/home/.cache/x", true, 13},
		{"dir/** matches deep", "/home/.cache/**", "/home/.cache/a/b/c", true, 13},

		// Question mark
		{"? matches one char", "/tmp/?.txt", "/tmp/a.txt", true, 9},
		{"? does not match slash", "/tmp/?/x", "/tmp//x", false, 0},
		{"? requires a char", "/tmp/?.txt", "/tmp/.txt", false, 0},

		// Leading dot is matched by * (unlike shell)
		{"star matches leading dot", "$HOME/.*", "$HOME/.ssh", true, 7},

		// Anchoring - pattern matches whole path
		{"no prefix match", "/home", "/home/user", false, 0},
		{"no suffix match", "user/file", "/home/user/file", false, 0},

		// Trailing slash normalised
		{"trailing slash on path", "/home/user/**", "/home/user/", true, 11},
		{"trailing slash on both", "/home/user/", "/home/user/", true, 10},

		// Patterns from the specificity table
		{"HOME dot star", "/home/tsaarni/.*", "/home/tsaarni/.ssh", true, 15},
		{"HOME work dstar", "/home/tsaarni/work/**", "/home/tsaarni/work/main.go", true, 19},
		{"HOME config dstar", "/home/tsaarni/.config/**", "/home/tsaarni/.config/git/config", true, 22},
		{"HOME config gravelpit dstar", "/home/tsaarni/.config/gravelpit/**", "/home/tsaarni/.config/gravelpit/x.yaml", true, 32},

		// SSH public parts
		{"ssh pub glob", "/home/user/.ssh/*.pub", "/home/user/.ssh/id_ed25519.pub", true, 20},
		{"ssh config exact", "/home/user/.ssh/config", "/home/user/.ssh/config", true, 22},

		// Does NOT match sibling with longer name (anchoring)
		{"no partial segment match", "/home/user/.ssh", "/home/user/.ssh_backup", false, 0},
		{"dot star anchored to segment", "/home/user/.*", "/home/user/.ssh_backup", true, 12},

		// Connect patterns
		{"run user star bus", "/run/user/*/bus", "/run/user/1000/bus", true, 14},
		{"run user star keyring dstar", "/run/user/*/keyring/**", "/run/user/1000/keyring/control", true, 19},
		{"run user star keyring ssh", "/run/user/*/keyring/ssh", "/run/user/1000/keyring/ssh", true, 22},

		// Empty path (connect event for path-based rules)
		{"empty path no match", "/home/**", "", false, 0},

		// Multiple single stars in sequence
		{"two stars in path", "/home/*/*/file", "/home/a/b/file", true, 12},

		// Dot-star pattern pair from secrets policy
		{"hidden file", "/home/tsaarni/.*", "/home/tsaarni/.newtool", true, 15},
		{"hidden deep", "/home/tsaarni/.*/**", "/home/tsaarni/.newtool/token", true, 16},
		{"non-hidden not matched", "/home/tsaarni/.*", "/home/tsaarni/work", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, score := PathMatch(tt.pattern, tt.path)
			if matched != tt.wantMatch {
				t.Errorf("PathMatch(%q, %q) matched = %v, want %v", tt.pattern, tt.path, matched, tt.wantMatch)
			}
			if score != tt.wantScore {
				t.Errorf("PathMatch(%q, %q) score = %d, want %d", tt.pattern, tt.path, score, tt.wantScore)
			}
		})
	}
}

func TestPatternScore(t *testing.T) {
	patterns := []struct {
		pattern string
		score   int
	}{
		{"/home/tsaarni/.*", 15},
		{"/home/tsaarni/work/**", 19},
		{"/home/tsaarni/.config/**", 22},
		{"/home/tsaarni/.config/gravelpit/**", 32},
	}

	for _, p := range patterns {
		actual := PatternScore(p.pattern)
		if actual != p.score {
			t.Errorf("PatternScore(%q) = %d, want %d", p.pattern, actual, p.score)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{
		"/home/user/**",
		"/home/user/.*",
		"/home/user/.ssh/*.pub",
		"/run/user/*/bus",
	}
	for _, p := range valid {
		if !ValidatePattern(p) {
			t.Errorf("ValidatePattern(%q) = false, want true", p)
		}
	}
}
