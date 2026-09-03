package discover

import (
	"strings"
	"testing"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

func TestGlobForPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"file in root", "/package.json", "/package.json"},
		{"file in top-level dir", "/home/package.json", "/home/package.json"},
		{"file in $HOME", "$HOME/.curlrc", "$HOME/.curlrc"},
		{"file in top-level $HOME dir", "$HOME/.local/package.json", "$HOME/.local/package.json"},
		{"deep $HOME path collapses", "$HOME/.config/pnpm/config.yaml", "$HOME/.config/pnpm/**"},
		{"deeper $HOME path collapses to two levels", "$HOME/.local/share/mise/installs/node", "$HOME/.local/share/**"},
		{"deep absolute path collapses", "/home/other/.cache/thing", "/home/other/**"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := globForPath(tc.path); got != tc.want {
				t.Errorf("globForPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestGlobForPathNeverBlanketsHome guards the regression that made a single
// denial on /home/package.json grant reads to every user's home directory,
// which then masked the specific paths a tool needs.
func TestGlobForPathNeverBlanketsHome(t *testing.T) {
	if got := globForPath("/home/package.json"); got == "/home/**" {
		t.Errorf("globForPath(/home/package.json) = %q, want an exact path", got)
	}
}

func TestIsProbeTemp(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/_tmp_35070_e65553809eed9d5d0a4c78e6cd0caa6d", true},
		{"/home/tsaarni/.local/share/pnpm/_tmp_32152_445bc47f6889f9250677f745198820c4", true},
		{"/home/tsaarni/.cache/pnpm/config.yaml", false},
		{"/tmp/regular-file", false},
		{"/home/tsaarni/_tmp_notaprobe", false},
	}

	for _, tc := range tests {
		if got := IsProbeTemp(tc.path); got != tc.want {
			t.Errorf("IsProbeTemp(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestGeneratePolicyDropsRootProbe checks a mount-point probe in "/" never
// reaches the policy: writes to the filesystem root must not be granted, and
// tools carry on when that probe is denied.
func TestGeneratePolicyDropsRootProbe(t *testing.T) {
	paths := []ActionPath{
		{Action: schema.ActionWrite, Path: "/_tmp_35070_e65553809eed9d5d0a4c78e6cd0caa6d"},
		{Action: schema.ActionWrite, Path: "/home/tsaarni/.cache/pnpm/metadata/registry.json"},
	}

	policy := GeneratePolicyFromPaths(paths, "node", "/home/tsaarni", "/nonexistent-workdir")

	if strings.Contains(policy, "_tmp_") {
		t.Errorf("policy contains a root probe:\n%s", policy)
	}
	if !strings.Contains(policy, `"$HOME/.cache/pnpm/**"`) {
		t.Errorf("policy missing the real cache path:\n%s", policy)
	}
}

// TestGeneratePolicyKeepsStoreProbe checks a probe outside "/" is kept, with the
// pid replaced by a wildcard. Dropping it would make pnpm relocate its store to
// whichever directory the profile sandbox happens to allow, so the profile would
// never record the store the tool really uses.
func TestGeneratePolicyKeepsStoreProbe(t *testing.T) {
	paths := []ActionPath{
		{Action: schema.ActionWrite, Path: "/home/tsaarni/.local/share/pnpm/_tmp_32152_445bc47f6889f9250677f745198820c4"},
		{Action: schema.ActionWrite, Path: "/home/tsaarni/.pnpm-store/_tmp_32152_445bc47f6889f9250677f745198820c4"},
	}

	policy := GeneratePolicyFromPaths(paths, "node", "/home/tsaarni", "/nonexistent-workdir")

	if strings.Contains(policy, "32152") {
		t.Errorf("policy kept the pid-specific probe name:\n%s", policy)
	}
	// Three levels deep, so it collapses to the two-level glob.
	if !strings.Contains(policy, `"$HOME/.local/share/**"`) {
		t.Errorf("policy missing the store directory:\n%s", policy)
	}
	// Two levels deep, so the generalized probe name is kept.
	if !strings.Contains(policy, `"$HOME/.pnpm-store/_tmp_*"`) {
		t.Errorf("policy missing the generalized probe pattern:\n%s", policy)
	}
}

// TestGeneratePolicyKeepsSpecificPathsVisible is the end-to-end form of the
// masking bug: a denial on /home/package.json must not produce a rule that also
// covers $HOME/.config/pnpm/config.yaml, otherwise later runs never report that
// path as denied and it is left out of the policy.
func TestGeneratePolicyKeepsSpecificPathsVisible(t *testing.T) {
	paths := []ActionPath{
		{Action: schema.ActionRead, Path: "/home/package.json"},
		{Action: schema.ActionRead, Path: "/home/tsaarni/.config/pnpm/config.yaml"},
	}

	policy := GeneratePolicyFromPaths(paths, "node", "/home/tsaarni", "/nonexistent-workdir")

	if strings.Contains(policy, `"/home/**"`) {
		t.Errorf("policy contains a blanket /home/** rule:\n%s", policy)
	}
	for _, want := range []string{`"/home/package.json"`, `"$HOME/.config/pnpm/**"`} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy missing %s:\n%s", want, policy)
		}
	}
}
