// cmd_run.go implements the "run" subcommand that runs a command inside a sandbox.
//
// The run process is both the child's parent and the supervisor: it loads policy,
// re-executes itself as the sandbox child (which installs the seccomp filter and
// sends back the notify fd), then handles notifications directly.
//
// Lifecycle:
//   - gravelpit run stays alive for the whole session. There is no detached mode.
//     It is the child's parent and the only process that can reap it. EOF on the
//     notif fd arrives only after every process using the filter has exited AND
//     been reaped.
//   - If gravelpit run exits early while daemonized grandchildren hold the
//     filter, those processes would have every intercepted syscall fail with
//     ENOSYS (documented kernel behaviour when the supervisor fd is closed).
//
// Supervisor death: if this process dies, intercepted syscalls in the sandbox
// return ENOSYS and the sandboxed processes keep running (not killed). This is
// documented kernel behaviour. SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV is
// unrelated to this - it only affects signal delivery while a notification is
// pending.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/tsaarni/gravelpit/internal/audit"
	"github.com/tsaarni/gravelpit/internal/config"
	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/process"
	"github.com/tsaarni/gravelpit/internal/rpc"
	"github.com/tsaarni/gravelpit/internal/sandbox"
	"github.com/tsaarni/gravelpit/internal/stats"
	"github.com/tsaarni/gravelpit/internal/supervisor"
	"github.com/tsaarni/gravelpit/pkg/schema"
)

func cmdRun() *cobra.Command {
	var logLevel string
	var policyDir string
	var envVars []string
	var auditFile string
	var auditLevel string
	var pprofAddr string
	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command inside a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if logLevel != "" {
				if err := config.ConfigureSlog(logLevel); err != nil {
					return err
				}
			}
			return runSandbox(policyDir, envVars, auditFile, auditLevel, pprofAddr, args)
		},
	}
	cmd.Flags().StringVar(&logLevel, "log-level", "", "Log level: debug, info, warn, error")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "Policy directory (default ~/.config/gravelpit/policies)")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil, "Set environment variable (KEY=VALUE)")
	cmd.Flags().StringVar(&auditFile, "audit-file", "", "Write audit log to this file")
	cmd.Flags().StringVar(&auditLevel, "audit-level", "", "Audit level: all, denials (default from config)")
	cmd.Flags().StringVar(&pprofAddr, "pprof", "", "Enable pprof HTTP server on this address (e.g. localhost:6060)")
	return cmd
}

func runSandbox(policyDir string, envVars []string, auditFile string, auditLevel string, pprofAddr string, args []string) error {
	// Save terminal state so we can restore it if the child dies without cleanup.
	var savedTermios *unix.Termios
	if termios, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err == nil {
		savedTermios = termios
	}
	restoreTerminal := func() {
		if savedTermios != nil {
			unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, savedTermios)
		}
	}

	if pprofAddr != "" {
		go func() {
			slog.Info("pprof server listening", "addr", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				slog.Warn("pprof server failed", "error", err)
			}
		}()
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Warn("config load error, using defaults", "error", err)
		cfg, _ = config.Load()
	}

	if policyDir == "" {
		policyDir = cfg.PolicyDir
	}

	// Expand ~ to home directory for actual filesystem access.
	expandedDir := policyDir
	if len(policyDir) > 0 && policyDir[0] == '~' {
		if home, err := os.UserHomeDir(); err == nil {
			expandedDir = home + policyDir[1:]
		}
	}

	// Load policy.
	engine, err := loadPolicy(expandedDir)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	// Engine is accessed via EngineFunc so reload can swap it atomically.
	var engineMu sync.RWMutex
	engineFunc := func() *policy.Engine {
		engineMu.RLock()
		defer engineMu.RUnlock()
		return engine
	}

	// Set up audit logging. CLI flags override config values.
	if auditFile == "" {
		auditFile = cfg.Audit.File
	}
	if auditLevel == "" {
		auditLevel = cfg.Audit.Level
	}

	var onDecision func(*schema.AuditRecord)
	if auditFile != "" {
		auditLogger, err := audit.New(auditFile, auditLevel)
		if err != nil {
			return fmt.Errorf("setting up audit log: %w", err)
		}
		defer auditLogger.Close()
		onDecision = auditLogger.Log
	}

	// Build the notification handler.
	procTable := process.New(cfg.Cache.ProcessEntries)
	statsCollector := stats.NewCollector()
	decisionCache := policy.NewCache(cfg.Cache.DecisionEntries)
	statsCollector.SetDecisionCacheFunc(decisionCache.Stats)
	statsCollector.SetProcessTableFunc(procTable.Stats, procTable.Lookups)
	// Sandbox identity, built once. The pid of this process identifies the
	// session; workdir is the same value $WORKDIR expands to in rules, so a rule
	// written against sandbox.workdir and one written against $WORKDIR agree.
	workdir, err := os.Getwd()
	if err != nil {
		slog.Warn("cannot determine working directory", "error", err)
	}
	sandboxInfo := schema.SandboxInfo{
		ID:      strconv.Itoa(os.Getpid()),
		Command: strings.Join(args, " "),
		Workdir: workdir,
	}

	handler := &supervisor.Handler{
		EngineFunc:         engineFunc,
		Cache:              decisionCache,
		OnDecision:         onDecision,
		ProcessTable:       procTable,
		Stats:              statsCollector,
		DefaultDenyMessage: cfg.DefaultDenyMessage,
		Sandbox:            sandboxInfo,
	}

	// Reload function triggered via RPC.
	reloadFn := func() error {
		slog.Info("reloading policy", "dir", policyDir)
		newEngine, err := loadPolicy(expandedDir)
		if err != nil {
			slog.Error("policy reload failed", "error", err)
			return err
		}
		engineMu.Lock()
		engine = newEngine
		engineMu.Unlock()
		decisionCache.Clear()
		statsCollector.RecordReload()
		slog.Info("policy reloaded")
		return nil
	}

	// Start the RPC socket server.
	statsSrv, err := stats.NewServer(statsCollector, reloadFn)
	if err != nil {
		slog.Warn("rpc server failed to start", "error", err)
	} else {
		go statsSrv.Serve()
		defer statsSrv.Close()
	}

	// Adopt orphaned descendants instead of letting init take them.
	//
	// A process that daemonizes in the sandbox (setsid, then parent exits) would
	// be reparented to systemd --user and leave the supervisor's process tree.
	// process_vm_readv then fails with EPERM, because yama ptrace_scope=1 allows
	// it only from an ancestor. Path arguments would decode as empty and no rule
	// would decide anything.
	if err := sandbox.SetChildSubreaper(); err != nil {
		slog.Warn("not a child subreaper: daemonized processes may be unreadable", "error", err)
	}

	// Socketpair for passing the seccomp notify fd from the child to us.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	parentFd := fds[0]
	childSock := os.NewFile(uintptr(fds[1]), "child-sock")

	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		unix.Close(parentFd)
		childSock.Close()
		return fmt.Errorf("reading /proc/self/exe: %w", err)
	}

	// Pass the RPC socket path to the sandboxed process.
	childEnv := append(os.Environ(), envVars...)
	if statsSrv != nil {
		childEnv = append(childEnv, fmt.Sprintf("%s=%s", rpc.EnvSockPath, statsSrv.SockPath()))
	}
	// Mark this re-execution as the sandbox child (see sandbox.IsSandboxChild).
	childEnv = append(childEnv, sandbox.EnvSandboxChild+"=1")

	// Re-execute ourselves with the target command as argv. The child inherits
	// childSock as fd 3 (the first ExtraFiles entry) and takes the sandbox
	// child branch in main.
	child := exec.Command(self, args...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.ExtraFiles = []*os.File{childSock}
	child.Env = childEnv

	if err := child.Start(); err != nil {
		unix.Close(parentFd)
		childSock.Close()
		return fmt.Errorf("starting sandbox child: %w", err)
	}
	childSock.Close()

	slog.Debug("sandbox child started, waiting for notif fd", "child_pid", child.Process.Pid)

	// Ensure parentFd is blocking.
	unix.SetNonblock(parentFd, false)

	notifFd, err := recvFd(parentFd)
	if err != nil {
		unix.Close(parentFd)
		child.Process.Kill()
		return fmt.Errorf("receiving notif fd: %w", err)
	}
	unix.Write(parentFd, []byte{1}) // ack
	unix.Close(parentFd)

	slog.Debug("received notif fd", "notif_fd", notifFd)
	fmt.Fprintf(os.Stderr, "\033[32m▶ gravelpit\033[0m sandbox policy=%s\n", policyDir)

	// Run notification handler loop in a goroutine.
	go handler.Run(notifFd)

	// Wait for child exit or signals.
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err := <-done:
			signal.Stop(sigCh)
			unix.Close(notifFd)
			restoreTerminal()
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return err
		case sig := <-sigCh:
			// The terminal already sent the signal to the foreground process
			// group, so the child got it too. Forward explicitly in case
			// gravelpit was signalled directly (not via terminal).
			child.Process.Signal(sig)
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
				// Child did not exit. Force kill it. When our direct child
				// dies, child.Wait returns. Grandchildren that escaped to
				// their own process group lose the seccomp notif fd when we
				// exit, which makes their next intercepted syscall fail.
				child.Process.Kill()
				<-done
			}
			restoreTerminal()
			os.Exit(128 + int(sig.(syscall.Signal)))
		}
	}
}

// loadPolicy loads and compiles policy rules from the given directory.
func loadPolicy(dir string) (*policy.Engine, error) {
	loader, err := policy.NewLoader()
	if err != nil {
		return nil, err
	}
	rules, errs := loader.LoadDir(dir)
	for _, e := range errs {
		slog.Warn("policy load error", "error", e)
	}

	// Compile built-in rules and prepend them.
	builtins, err := policy.BuiltinRules()
	if err != nil {
		slog.Warn("failed to compile built-in rules", "error", err)
		builtins = nil
	}

	allRules := append(builtins, rules...)
	return policy.NewEngine(allRules), nil
}

// recvFd receives a single file descriptor via SCM_RIGHTS.
func recvFd(sockFd int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFd, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, cmsg := range cmsgs {
		if fds, err := unix.ParseUnixRights(&cmsg); err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no fd received")
}
