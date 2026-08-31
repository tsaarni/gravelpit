// verify.go discovers and verifies minimal policies for tool profiles.
//
// Each profile is a directory under profiles/ containing run.sh (the workflow)
// and an optional fixture/ directory (source files). This tool runs each
// profile inside the gravelpit sandbox and either generates a policy covering
// all denied accesses (record mode) or verifies that an existing generated
// policy has zero denials (verify mode).
//
// Usage:
//
//	go run profiles/verify.go --record          generate all profiles
//	go run profiles/verify.go --record go       generate one profile
//	go run profiles/verify.go                   verify all profiles
//	go run profiles/verify.go go                verify one profile
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tsaarni/gravelpit/internal/discover"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

func main() {
	record := flag.Bool("record", false, "Generate policies (default: verify)")
	flag.Parse()
	filter := flag.Arg(0)

	profilesDir, err := findProfilesDir()
	if err != nil {
		fatal("finding profiles directory: %v", err)
	}

	gravelpit := filepath.Join(filepath.Dir(profilesDir), "bin", "gravelpit")
	if _, err := os.Stat(gravelpit); err != nil {
		fatal("gravelpit binary not found at %s, run 'make build' first", gravelpit)
	}

	generatedDir := filepath.Join(profilesDir, "generated")
	basePolicyPath := filepath.Join(profilesDir, "base-policy.yaml")

	profiles := discoverProfiles(profilesDir)
	if len(profiles) == 0 {
		fatal("no profiles found in %s", profilesDir)
	}

	var passed, failed, skipped int

	for _, p := range profiles {
		if filter != "" && p.name != filter {
			continue
		}

		if !checkAvailable(p, gravelpit) {
			fmt.Printf("SKIP  %s (tool not available)\n", p.name)
			skipped++
			continue
		}

		if *record {
			err := runRecord(p, gravelpit, basePolicyPath, generatedDir)
			if err != nil {
				fmt.Printf("RECORD  %s ... FAIL: %v\n", p.name, err)
				failed++
			} else {
				passed++
			}
		} else {
			err := runVerify(p, gravelpit, basePolicyPath, generatedDir)
			if err != nil {
				fmt.Printf("VERIFY  %s ... FAIL: %v\n", p.name, err)
				failed++
			} else {
				fmt.Printf("VERIFY  %s ... ok\n", p.name)
				passed++
			}
		}
	}

	fmt.Printf("\n%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	if failed > 0 {
		os.Exit(1)
	}
}

type profile struct {
	name string
	dir  string
}

func discoverProfiles(root string) []profile {
	toolsDir := filepath.Join(root, "tools")
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		return nil
	}
	var profiles []profile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(toolsDir, e.Name(), "run.sh")); err == nil {
			profiles = append(profiles, profile{name: e.Name(), dir: filepath.Join(toolsDir, e.Name())})
		}
	}
	return profiles
}

func checkAvailable(p profile, gravelpit string) bool {
	cmd := exec.Command("bash", filepath.Join(p.dir, "run.sh"), "--check")
	cmd.Env = append(os.Environ(), "GRAVELPIT_BIN="+gravelpit)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// runRecord iterates until no new denials appear, collecting denied (action,
// path) pairs across all iterations via the audit log. Generates one clean
// policy file at the end.
func runRecord(p profile, gravelpit, basePolicyPath, generatedDir string) error {
	if err := os.MkdirAll(generatedDir, 0755); err != nil {
		return err
	}

	outfile := filepath.Join(generatedDir, p.name+".yaml")
	homeDir, _ := os.UserHomeDir()

	var allPaths []discover.ActionPath

	fmt.Printf("RECORD  %s ... ", p.name)

	var iteration int
	for iteration = 0; iteration < 10; iteration++ {
		workdir, cleanup, err := setupWorkdir(p)
		if err != nil {
			return err
		}

		policyDir, policyCleanup, err := buildPolicyDir(basePolicyPath, outfile)
		if err != nil {
			cleanup()
			return err
		}

		// Use audit file to capture structured records.
		auditFile := filepath.Join(workdir, ".audit.jsonl")
		runGravelpit(gravelpit, policyDir, workdir, auditFile)

		policyCleanup()

		newPaths := readDeniedPaths(auditFile)
		cleanup()

		if len(newPaths) == 0 {
			break
		}

		allPaths = append(allPaths, newPaths...)

		// Write intermediate policy for the next iteration.
		intermediate := discover.GeneratePolicyFromPaths(allPaths, p.name, homeDir, "/nonexistent-workdir")
		os.WriteFile(outfile, []byte(intermediate), 0644)
	}

	if len(allPaths) == 0 {
		os.Remove(outfile)
	} else {
		// Use a workdir path that won't match any real path, so only $HOME
		// substitution takes effect.
		policy := discover.GeneratePolicyFromPaths(allPaths, p.name, homeDir, "/nonexistent-workdir")
		if err := os.WriteFile(outfile, []byte(policy), 0644); err != nil {
			return err
		}
	}

	fmt.Printf("ok (%d iterations)\n", iteration+1)
	return nil
}

// runVerify runs the profile with base + generated policy and checks the audit
// log for denials.
func runVerify(p profile, gravelpit, basePolicyPath, generatedDir string) error {
	workdir, cleanup, err := setupWorkdir(p)
	if err != nil {
		return err
	}
	defer cleanup()

	generated := filepath.Join(generatedDir, p.name+".yaml")
	policyDir, policyCleanup, err := buildPolicyDir(basePolicyPath, generated)
	if err != nil {
		return err
	}
	defer policyCleanup()

	auditFile := filepath.Join(workdir, ".audit.jsonl")
	runGravelpit(gravelpit, policyDir, workdir, auditFile)

	denials := readDeniedPaths(auditFile)
	if len(denials) > 0 {
		// Show the first few.
		for i, d := range denials {
			if i >= 5 {
				break
			}
			fmt.Printf("\n  denied: %s %s", d.Action, d.Path)
		}
		fmt.Println()
		return fmt.Errorf("%d denials", len(denials))
	}
	return nil
}

// readDeniedPaths reads the JSON-lines audit log and returns denied (action, path)
// pairs, excluding exec, connect, and unresolved-path denials.
func readDeniedPaths(path string) []discover.ActionPath {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var paths []discover.ActionPath
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec schema.AuditRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Verdict != schema.VerdictDeny {
			continue
		}
		if rec.Action == schema.ActionExec || rec.Action == schema.ActionConnect {
			continue
		}
		if rec.Unresolved != "" {
			continue
		}
		paths = append(paths, discover.ActionPath{Action: rec.Action, Path: rec.Path})
	}
	return paths
}

func setupWorkdir(p profile) (string, func(), error) {
	workdir, err := os.MkdirTemp("", "gravelpit-profile-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(workdir) }

	// Copy run.sh into workdir so sandbox reads don't reference the source tree.
	data, err := os.ReadFile(filepath.Join(p.dir, "run.sh"))
	if err != nil {
		cleanup()
		return "", nil, err
	}
	os.WriteFile(filepath.Join(workdir, "run.sh"), data, 0755)

	// Copy fixtures.
	fixtureDir := filepath.Join(p.dir, "fixture")
	if info, err := os.Stat(fixtureDir); err == nil && info.IsDir() {
		filepath.WalkDir(fixtureDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(fixtureDir, path)
			target := filepath.Join(workdir, rel)
			if d.IsDir() {
				return os.MkdirAll(target, 0755)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0644)
		})
	}

	return workdir, cleanup, nil
}

func buildPolicyDir(basePolicyPath, generatedPath string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "gravelpit-policy-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	data, err := os.ReadFile(basePolicyPath)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	os.WriteFile(filepath.Join(dir, "base-policy.yaml"), data, 0644)

	if generatedPath != "" {
		if data, err := os.ReadFile(generatedPath); err == nil {
			os.WriteFile(filepath.Join(dir, filepath.Base(generatedPath)), data, 0644)
		}
	}

	return dir, cleanup, nil
}

func runGravelpit(gravelpit, policyDir, workdir, auditFile string) {
	args := []string{"run", "--policy-dir=" + policyDir, "--audit-file=" + auditFile, "--audit-level=all", "--", "bash", "run.sh"}
	cmd := exec.Command(gravelpit, args...)
	cmd.Dir = workdir
	// GRAVELPIT_BIN lets a profile's run.sh invoke the gravelpit CLI itself
	// (e.g. "gravelpit policy lint") from inside the sandbox it is testing,
	// without depending on it being installed on PATH.
	cmd.Env = append(os.Environ(), "GRAVELPIT_BIN="+gravelpit)
	cmd.Run()
}

func findProfilesDir() (string, error) {
	for _, candidate := range []string{"profiles", "."} {
		abs, _ := filepath.Abs(candidate)
		if _, err := os.Stat(filepath.Join(abs, "base-policy.yaml")); err == nil {
			return abs, nil
		}
	}
	return "", fmt.Errorf("cannot find profiles directory (looked for base-policy.yaml)")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
