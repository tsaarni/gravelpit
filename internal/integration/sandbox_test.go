// Package integration tests the full seccomp-notify path with real syscall interception.
//
// The test uses a self-re-exec pattern: the test binary re-launches itself as
// the sandboxed child process. TestMain checks for an environment variable and,
// if set, runs the probe logic (install seccomp filter, perform syscalls, exit)
// instead of running tests. This avoids needing a separately compiled binary.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/config"
	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/process"
	"github.com/tsaarni/gravelpit/internal/seccomp"
	"github.com/tsaarni/gravelpit/internal/stats"
	"github.com/tsaarni/gravelpit/internal/supervisor"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

func TestMain(m *testing.M) {
	// When this env var is set, the binary was re-exec'd as the sandboxed probe.
	// MUDPIT_PROBE names which probe set to run, so several tests can share the
	// re-exec harness with different syscall sequences.
	switch os.Getenv("MUDPIT_PROBE") {
	case "":
		os.Exit(m.Run())
	case "default":
		runProbe(probeDefault)
	case "suppress":
		runProbe(probeSuppress)
	case "execchild":
		runProbe(probeExecChild)
	case "cache":
		runProbe(probeCache)
	case "enrich":
		runProbe(probeEnrich)
	case "forkonly":
		runProbe(probeForkOnly)
	case "syscallvar":
		runProbe(probeSyscallVar)
	default:
		fmt.Fprintf(os.Stderr, "probe: unknown probe set %q\n", os.Getenv("MUDPIT_PROBE"))
		os.Exit(2)
	}
}

// sandboxOpts configures a supervised probe run.
type sandboxOpts struct {
	rules              []*policy.CompiledRule
	probeSet           string // value passed as MUDPIT_PROBE to the child
	defaultDenyMessage string
	homeDir            string
	workDir            string
	cache              *policy.Cache // nil disables the decision cache
	sandbox            schema.SandboxInfo
}

// sandboxResult holds everything observable about a probe run.
type sandboxResult struct {
	records []*schema.AuditRecord
	stderr  string
	stats   *stats.Collector
}

// runSandbox re-execs the test binary as a sandboxed child, supervises it with
// the real supervisor.Handler, and returns the audit records it produced, the
// child's stderr, and the stats collector.
//
// Audit records are collected under a mutex: the handler answers each
// notification from its own goroutine. Records are complete by the time the
// child exits, because HandleSyscall calls OnDecision before responding, so the
// child cannot proceed past a syscall whose record is still pending.
func runSandbox(t *testing.T, opts sandboxOpts) sandboxResult {
	t.Helper()

	engine := policy.NewEngine(opts.rules)

	// Use a socketpair to pass the notif fd from child to parent.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "parent")
	childSock := os.NewFile(uintptr(fds[1]), "child")

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(self, "-test.run=^$")
	cmd.Stdout = os.Stdout
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	cmd.ExtraFiles = []*os.File{childSock} // fd 3 in child
	cmd.Env = append(os.Environ(),
		"MUDPIT_PROBE="+opts.probeSet,
		"MUDPIT_HOME="+opts.homeDir,
		"MUDPIT_WORK="+opts.workDir,
		"HOME="+opts.homeDir,
	)

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting probe: %v", err)
	}
	childSock.Close()

	notifFd := receiveNotifFd(t, int(parentSock.Fd()))

	// Signal child to proceed.
	unix.Write(int(parentSock.Fd()), []byte{1})

	var mu sync.Mutex
	var records []*schema.AuditRecord
	collector := stats.NewCollector()
	procTable := process.New(config.DefaultProcessEntries)
	// Register the size sources the same way cmd_run does, so a test can read
	// entry counts and byte estimates from the summary.
	if opts.cache != nil {
		collector.SetDecisionCacheFunc(opts.cache.Stats)
	}
	collector.SetProcessTableFunc(procTable.Stats, procTable.Lookups)
	handler := &supervisor.Handler{
		Engine:             engine,
		Cache:              opts.cache,
		Stats:              collector,
		ProcessTable:       procTable,
		DefaultDenyMessage: opts.defaultDenyMessage,
		Sandbox:            opts.sandbox,
		OnDecision: func(r *schema.AuditRecord) {
			mu.Lock()
			records = append(records, r)
			mu.Unlock()
		},
	}

	done := make(chan struct{})
	go func() {
		handler.Run(notifFd)
		close(done)
	}()

	cmd.Wait()
	parentSock.Close()
	unix.Close(notifFd)
	<-done

	mu.Lock()
	defer mu.Unlock()
	return sandboxResult{records: records, stderr: stderrBuf.String(), stats: collector}
}

// TestSandboxProbe installs a seccomp filter in a child process, supervises it
// using the real supervisor.Handler, and verifies verdicts and stderr messages.
func TestSandboxProbe(t *testing.T) {
	// Create a temporary directory structure for the probe.
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "testuser")
	workDir := filepath.Join(homeDir, "work", "project")
	secretDir := filepath.Join(homeDir, ".ssh")
	cacheDir := filepath.Join(homeDir, ".cache", "builds")

	for _, d := range []string{workDir, secretDir, cacheDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create test files.
	writeFile(t, filepath.Join(secretDir, "id_rsa"), "SECRET KEY")
	writeFile(t, filepath.Join(secretDir, "config"), "Host *\n")
	writeFile(t, filepath.Join(workDir, "main.go"), "package main\n")
	writeFile(t, filepath.Join(cacheDir, "obj.o"), "ELF...")

	// Set up the policy engine.
	rules := buildTestRules(homeDir)

	res := runSandbox(t, sandboxOpts{
		rules:    rules,
		probeSet: "default",
		homeDir:  homeDir,
		workDir:  workDir,
	})

	// Verify verdicts.
	t.Logf("Collected %d records:", len(res.records))
	for _, r := range res.records {
		ruleName := "default"
		if r.Rule != nil {
			ruleName = r.Rule.Name
		}
		t.Logf("  %-8s %-5s %-60s %s", r.Syscall.Name, r.Verdict, r.Path, ruleName)
	}
	verifyRecords(t, res.records)

	// Verify stderr messages.
	t.Logf("Probe stderr:\n%s", res.stderr)
	verifyStderrMessages(t, res.stderr, homeDir)
}

// runProbe is the entry point for the re-exec'd child process. It installs a
// seccomp filter, sends the notification fd to the parent, then runs probe to
// perform syscalls that the parent's supervisor intercepts and evaluates.
func runProbe(probe func(homeDir, workDir string)) {
	runtime.LockOSThread()

	homeDir := os.Getenv("MUDPIT_HOME")
	workDir := os.Getenv("MUDPIT_WORK")
	sockFd := 3 // passed via cmd.ExtraFiles

	if homeDir == "" || workDir == "" {
		fmt.Fprintf(os.Stderr, "probe: MUDPIT_HOME and MUDPIT_WORK must be set\n")
		os.Exit(1)
	}

	// Required for unprivileged seccomp.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "probe: prctl(NO_NEW_PRIVS): %v\n", err)
		os.Exit(2)
	}

	// Install the seccomp filter and get the notification fd.
	filter := seccomp.BuildFilter()
	notifFd, err := installFilter(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: seccomp: %v\n", err)
		os.Exit(2)
	}

	// Send the notif fd to the parent via SCM_RIGHTS.
	if err := sendFd(sockFd, notifFd); err != nil {
		fmt.Fprintf(os.Stderr, "probe: sendfd: %v\n", err)
		os.Exit(2)
	}

	unix.Close(notifFd)

	// Wait for parent to acknowledge before performing probes.
	buf := make([]byte, 1)
	unix.Read(sockFd, buf)
	unix.Close(sockFd)

	// Perform syscalls that the supervisor will intercept.
	probe(homeDir, workDir)
}

// probeDefault exercises reads, writes, deletes and mkdirs against the policy in
// buildTestRules.
func probeDefault(homeDir, workDir string) {
	probeReads(homeDir, workDir)
	probeWrites(homeDir, workDir)
	probeDeletes(homeDir, workDir)
	probeMkdirs(homeDir, workDir)
}

func probeReads(homeDir, workDir string) {
	// Allowed: workspace file.
	tryOpen(filepath.Join(workDir, "main.go"), unix.O_RDONLY)
	// Allowed: cache file (more specific than block-hidden).
	tryOpen(filepath.Join(homeDir, ".cache", "builds", "obj.o"), unix.O_RDONLY)
	// Denied: secret file.
	tryOpen(filepath.Join(homeDir, ".ssh", "id_rsa"), unix.O_RDONLY)
}

func probeWrites(homeDir, workDir string) {
	// Allowed: workspace file.
	tryOpen(filepath.Join(workDir, "new.go"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC)
	// Denied: dotfile in home.
	tryOpen(filepath.Join(homeDir, ".bashrc"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC)
}

func probeDeletes(homeDir, workDir string) {
	// Create the file first so unlink has something to operate on.
	tryOpen(filepath.Join(workDir, "deleteme.tmp"), unix.O_WRONLY|unix.O_CREAT)
	unix.Unlink(filepath.Join(workDir, "deleteme.tmp"))

	// Denied: delete outside workspace.
	unix.Unlink(filepath.Join(homeDir, ".ssh", "config"))
}

func probeMkdirs(homeDir, workDir string) {
	// Allowed: mkdir in workspace.
	unix.Mkdir(filepath.Join(workDir, "newdir"), 0755)
	// Denied: mkdir hidden dir.
	unix.Mkdir(filepath.Join(homeDir, ".newdir"), 0755)
}

func tryOpen(path string, flags int) {
	fd, err := unix.Open(path, flags, 0644)
	if err == nil {
		unix.Close(fd)
	}
}

func installFilter(filter []unix.SockFilter) (int, error) {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, NEW_LISTENER): %v", errno)
	}
	return int(fd), nil
}

func sendFd(sockFd, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(sockFd, []byte{0}, rights, nil, 0)
}

func buildTestRules(homeDir string) []*policy.CompiledRule {
	env, err := policy.NewCELEnv()
	if err != nil {
		panic(err)
	}

	rawRules := []policy.Rule{
		{
			Name:    "allow-reads",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictAllow,
			Match:   "true",
		},
		{
			Name:    "block-hidden",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictDeny,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/.*") || pathMatch(path, "%s/.*/**")`, homeDir, homeDir),
			Message: "Reading '${path}' is blocked by sandbox policy.",
		},
		{
			Name:    "allow-cache",
			Actions: []policy.Action{policy.ActionRead},
			Verdict: policy.VerdictAllow,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/.cache/**")`, homeDir),
		},
		{
			Name:    "allow-workspace-write",
			Actions: []policy.Action{policy.ActionWrite, policy.ActionDelete},
			Verdict: policy.VerdictAllow,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/work/**")`, homeDir),
		},
		{
			Name:    "deny-writes",
			Actions: []policy.Action{policy.ActionWrite, policy.ActionDelete},
			Verdict: policy.VerdictDeny,
			Match:   "true",
			Message: "Writing '${path}' is blocked by sandbox policy.",
		},
		{
			Name:    "allow-exec",
			Actions: []policy.Action{policy.ActionExec},
			Verdict: policy.VerdictAllow,
			Match:   "true",
		},
		{
			Name:    "allow-connect",
			Actions: []policy.Action{policy.ActionConnect},
			Verdict: policy.VerdictAllow,
			Match:   "true",
		},
		{
			Name:    "allow-metadata",
			Actions: []policy.Action{policy.ActionMetadata},
			Verdict: policy.VerdictAllow,
			Match:   fmt.Sprintf(`pathMatch(path, "%s/work/**")`, homeDir),
		},
	}

	var compiled []*policy.CompiledRule
	for i := range rawRules {
		cr, err := policy.CompileRule(env, &rawRules[i])
		if err != nil {
			panic(fmt.Sprintf("compiling rule %q: %v", rawRules[i].Name, err))
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

func verifyRecords(t *testing.T, records []*schema.AuditRecord) {
	t.Helper()

	type expect struct {
		desc         string
		pathContains string
		verdict      policy.Verdict
		rule         string
	}
	expectations := []expect{
		{"read workspace file", "/work/project/main.go", policy.VerdictAllow, "allow-reads"},
		{"read cache file", "/.cache/builds/obj.o", policy.VerdictAllow, "allow-cache"},
		{"read secret key", "/.ssh/id_rsa", policy.VerdictDeny, "block-hidden"},
		{"write workspace file", "/work/project/new.go", policy.VerdictAllow, "allow-workspace-write"},
		{"write .bashrc", "/.bashrc", policy.VerdictDeny, "deny-writes"},
		{"delete workspace file", "/work/project/deleteme.tmp", policy.VerdictAllow, "allow-workspace-write"},
		{"delete secret config", "/.ssh/config", policy.VerdictDeny, "deny-writes"},
		{"mkdir in workspace", "/work/project/newdir", policy.VerdictAllow, "allow-workspace-write"},
		{"mkdir hidden", "/.newdir", policy.VerdictDeny, "deny-writes"},
	}

	for _, exp := range expectations {
		found := false
		for _, r := range records {
			ruleName := ""
			if r.Rule != nil {
				ruleName = r.Rule.Name
			}
			if strings.Contains(r.Path, exp.pathContains) && r.Verdict == exp.verdict && ruleName == exp.rule {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FAIL: %s - expected %s for path containing %q (rule: %s)",
				exp.desc, exp.verdict, exp.pathContains, exp.rule)
		}
	}
}

func verifyStderrMessages(t *testing.T, stderr string, homeDir string) {
	t.Helper()

	expectations := []struct {
		desc     string
		contains string
	}{
		{"hidden file read denial", filepath.Join(homeDir, ".ssh", "id_rsa")},
		{"bashrc write denial", filepath.Join(homeDir, ".bashrc")},
		{"ssh config denial", filepath.Join(homeDir, ".ssh", "config")},
		{"hidden mkdir denial", filepath.Join(homeDir, ".newdir")},
	}

	for _, exp := range expectations {
		if !strings.Contains(stderr, exp.contains) {
			t.Errorf("stderr missing message for %s (expected path %q in output)", exp.desc, exp.contains)
		}
	}

	if !strings.Contains(stderr, "[gravelpit]") {
		t.Error("stderr messages should have [gravelpit] prefix")
	}

	if !strings.Contains(stderr, "blocked by sandbox policy") {
		t.Error("stderr messages should contain policy explanation")
	}
}

func receiveNotifFd(t *testing.T, sockFd int) int {
	t.Helper()
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFd, buf, oob, 0)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) == 0 {
		t.Fatal("no SCM_RIGHTS received")
	}
	fds, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil || len(fds) == 0 {
		t.Fatal("no fd in SCM_RIGHTS")
	}
	return fds[0]
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
