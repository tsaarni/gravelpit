// Package discover generates policy YAML from audit records collected during a
// sandbox run. Used by "gravelpit run --discover=file" to produce a policy
// fragment that would allow everything the command accessed.
package discover

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

// Collector accumulates audit records in memory. Safe for concurrent use.
type Collector struct {
	mu      sync.Mutex
	records []*schema.AuditRecord
}

// Record adds an audit record. Called from the handler's OnDecision callback.
func (c *Collector) Record(r *schema.AuditRecord) {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
}

// Records returns all collected records.
func (c *Collector) Records() []*schema.AuditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*schema.AuditRecord, len(c.records))
	copy(out, c.records)
	return out
}

// GeneratePolicy produces a YAML policy from audit records. Paths under system
// directories and the workspace are excluded since they belong in a shared base
// policy. Remaining paths under homeDir are collapsed into directory glob
// patterns.
//
// name is used for the rule name prefix and the header comment.
func GeneratePolicy(records []*schema.AuditRecord, name, homeDir, workDir string) string {
	var paths []ActionPath
	for _, rec := range records {
		if rec.Verdict != schema.VerdictDeny {
			continue
		}
		if rec.Action == schema.ActionExec || rec.Action == schema.ActionConnect {
			continue
		}
		if rec.Unresolved != "" {
			continue
		}
		paths = append(paths, ActionPath{Action: rec.Action, Path: rec.Path})
	}
	return GeneratePolicyFromPaths(paths, name, homeDir, workDir)
}

// ActionPath is an (action, path) pair collected from audit records.
type ActionPath struct {
	Action schema.Action
	Path   string
}

// GeneratePolicyFromPaths produces a YAML policy from raw (action, path) pairs.
// Paths under system directories and the workspace are excluded. Remaining
// paths are collapsed into glob patterns.
func GeneratePolicyFromPaths(paths []ActionPath, name, homeDir, workDir string) string {
	type key struct {
		action schema.Action
		path   string
	}
	seen := map[key]bool{}
	for _, ap := range paths {
		path := normalizePath(ap.Path, homeDir, workDir)
		if isBasePath(path) {
			continue
		}
		seen[key{ap.Action, path}] = true
	}

	actionOrder := []schema.Action{
		schema.ActionRead, schema.ActionWrite, schema.ActionDelete, schema.ActionMetadata,
	}

	var groups []actionPaths
	for _, action := range actionOrder {
		var paths []string
		for k := range seen {
			if k.action == action {
				paths = append(paths, k.path)
			}
		}
		if len(paths) == 0 {
			continue
		}
		groups = append(groups, actionPaths{action: action, dirs: collapseToGlobs(paths)})
	}

	groups = mergeActions(groups)
	return renderYAML(groups, name)
}

// actionPaths groups glob patterns for one or more combined actions.
type actionPaths struct {
	action schema.Action
	dirs   []string
}

// System path prefixes that belong in a shared base policy, not per-tool.
var basePrefixes = []string{
	"/usr/", "/lib/", "/lib64/", "/etc/", "/proc/", "/sys/", "/dev/",
	"/run/", "/bin/", "/sbin/", "/snap/", "/opt/", "/tmp/", "/var/tmp/",
	"/dev/shm/",
}

func isBasePath(normalized string) bool {
	if normalized == "" || normalized == "/" || normalized == "$HOME" {
		return true
	}
	// /home (the parent of every user's home directory) shows up as its own
	// denial whenever something canonicalizes a $HOME-relative path by
	// walking it component by component (e.g. symlink resolution), touching
	// every ancestor directory on the way down. It is as much a "given" as
	// $HOME itself, so it belongs in the same base-policy exclusion.
	if normalized == "/home" {
		return true
	}
	if normalized == "/tmp" || normalized == "/dev/null" {
		return true
	}
	for _, p := range basePrefixes {
		if strings.HasPrefix(normalized, p) {
			return true
		}
	}
	return strings.HasPrefix(normalized, "$WORKDIR/") || normalized == "$WORKDIR"
}

func normalizePath(path, homeDir, workDir string) string {
	// Replace workDir first since it is more specific (usually inside homeDir).
	path = strings.Replace(path, workDir, "$WORKDIR", 1)
	path = strings.Replace(path, homeDir, "$HOME", 1)
	return path
}

// collapseToGlobs groups paths into sorted, deduplicated glob patterns.
func collapseToGlobs(paths []string) []string {
	dirs := map[string]bool{}
	for _, p := range paths {
		g := globForPath(p)
		if g == "/**" || g == "//**" || g == "./**" {
			continue
		}
		dirs[g] = true
	}

	sorted := make([]string, 0, len(dirs))
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)

	// Remove patterns covered by a broader one.
	var deduped []string
	for _, pat := range sorted {
		covered := false
		for _, broader := range sorted {
			if broader == pat {
				continue
			}
			if strings.HasSuffix(broader, "/**") {
				prefix := strings.TrimSuffix(broader, "**")
				if strings.HasPrefix(pat, prefix) {
					covered = true
					break
				}
			}
		}
		if !covered {
			deduped = append(deduped, pat)
		}
	}
	return deduped
}

// globForPath returns a glob pattern covering the given path. For $HOME paths,
// uses two directory levels for specificity (e.g. $HOME/.config/go/**).
// Files directly in a top-level $HOME directory (e.g. $HOME/.config/curlrc)
// are kept as exact paths to avoid overly broad patterns.
func globForPath(path string) string {
	if !strings.HasPrefix(path, "$HOME/") {
		// Files directly in root (e.g. /uv.toml) are kept as exact paths.
		dir := filepath.Dir(path)
		if dir == "/" {
			return path
		}
		return dir + "/**"
	}

	rel := strings.TrimPrefix(path, "$HOME/")
	parts := strings.SplitN(rel, "/", 3)

	// Single component: file directly in $HOME (e.g. $HOME/.curlrc).
	if len(parts) == 1 {
		return path
	}

	// Two components: file directly in a top-level dir (e.g. $HOME/.config/curlrc).
	// Keep as exact path to avoid matching everything in that directory.
	if len(parts) == 2 {
		return path
	}

	// Three or more: collapse to two-level glob (e.g. $HOME/.config/go/**).
	return "$HOME/" + parts[0] + "/" + parts[1] + "/**"
}

// mergeActions combines groups with identical glob sets into a single rule
// with multiple actions (e.g. [write, delete]).
func mergeActions(groups []actionPaths) []actionPaths {
	var merged []actionPaths
	used := make([]bool, len(groups))

	for i := range groups {
		if used[i] {
			continue
		}
		g := groups[i]
		for j := i + 1; j < len(groups); j++ {
			if used[j] {
				continue
			}
			if sameDirs(g.dirs, groups[j].dirs) {
				g.action = g.action + "," + groups[j].action
				used[j] = true
			}
		}
		merged = append(merged, actionPaths{action: g.action, dirs: g.dirs})
	}
	return merged
}

func sameDirs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func renderYAML(groups []actionPaths, name string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("# Generated policy for %s.\n", name))
	buf.WriteString("# Review and trim before committing.\n")

	for i, g := range groups {
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString("\n")

		actions := actionLabel(g.action)
		ruleName := fmt.Sprintf("%s-%s", name, ruleNameSuffix(g.action))

		buf.WriteString(fmt.Sprintf("- name: %s\n", ruleName))
		buf.WriteString(fmt.Sprintf("  action: %s\n", actions))
		buf.WriteString("  verdict: allow\n")

		if len(g.dirs) == 1 {
			buf.WriteString(fmt.Sprintf("  match: pathMatch(path, \"%s\")\n", g.dirs[0]))
		} else {
			buf.WriteString("  match: >\n")
			for j, d := range g.dirs {
				if j < len(g.dirs)-1 {
					buf.WriteString(fmt.Sprintf("    pathMatch(path, \"%s\") ||\n", d))
				} else {
					buf.WriteString(fmt.Sprintf("    pathMatch(path, \"%s\")\n", d))
				}
			}
		}
	}

	return buf.String()
}

func actionLabel(action schema.Action) string {
	if strings.Contains(string(action), ",") {
		parts := strings.Split(string(action), ",")
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return string(action)
}

func ruleNameSuffix(action schema.Action) string {
	if strings.Contains(string(action), ",") {
		return "rw"
	}
	return string(action)
}
