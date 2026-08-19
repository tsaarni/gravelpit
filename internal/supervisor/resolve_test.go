// resolve_test.go tests symlink canonicalization of the directory part.
package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalizePathSymlinkDir checks a symlinked directory is resolved while
// the final component is left alone.
func TestCanonicalizePathSymlinkDir(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got := CanonicalizePath(filepath.Join(link, "file.txt"))
	want := filepath.Join(real, "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizePathFinalSymlinkKept checks the final component is not
// followed. For unlink and rename the link itself is the target, and for create
// the name may not exist yet.
func TestCanonicalizePathFinalSymlinkKept(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if got := CanonicalizePath(link); got != link {
		t.Errorf("got %q, want the link itself %q", got, link)
	}
}

// TestCanonicalizePathMissingLeafUnderSymlink checks a symlinked parent is still
// resolved when the leaf directory does not exist yet.
//
// This is the mkdir -p case. Resolving only when the whole directory chain
// exists would let policy see a path the kernel never writes to.
func TestCanonicalizePathMissingLeafUnderSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got := CanonicalizePath(filepath.Join(link, "new", "deep", "file.txt"))
	want := filepath.Join(real, "new", "deep", "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizePathDotDot checks ".." is resolved by the kernel walk.
func TestCanonicalizePathDotDot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	got := CanonicalizePath(filepath.Join(sub, "..", "file.txt"))
	want := filepath.Join(root, "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizePathNonExistent checks a path in a tree that does not exist is
// returned lexically cleaned. This is a normal case, not a failure.
func TestCanonicalizePathNonExistent(t *testing.T) {
	got := CanonicalizePath("/nonexistent-gp/a/b/../c/file.txt")
	want := "/nonexistent-gp/a/c/file.txt"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizePathRelativeUnchanged checks a relative path is passed through
// untouched. Callers resolve first; canonicalization must not silently
// interpret it against the supervisor cwd.
func TestCanonicalizePathRelativeUnchanged(t *testing.T) {
	if got := CanonicalizePath("rel/file.txt"); got != "rel/file.txt" {
		t.Errorf("got %q, want it unchanged", got)
	}
	if got := CanonicalizePath(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestCanonicalizePathRoot checks paths directly under root.
func TestCanonicalizePathRoot(t *testing.T) {
	if got := CanonicalizePath("/etc"); got != "/etc" {
		t.Errorf("got %q, want /etc", got)
	}
	if got := CanonicalizePath("/"); got != "/" {
		t.Errorf("got %q, want /", got)
	}
}
