// cmd_policy.go implements the "policy lint", "policy reload", "policy eval", and "policy explain" subcommands.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tsaarni/gravelpit/internal/config"
	"github.com/tsaarni/gravelpit/internal/policy"
	"github.com/tsaarni/gravelpit/internal/rpc"
	"github.com/tsaarni/gravelpit/internal/supervisor"
)

func cmdPolicy() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Policy management commands"}

	var policyDir string

	lint := &cobra.Command{
		Use:   "lint",
		Short: "Check policy files for errors",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolvePolicyDir(policyDir)
			if err != nil {
				return err
			}
			result := policy.Lint(dir)
			if !result.Ok() {
				for _, e := range result.Errors {
					fmt.Fprintf(os.Stderr, "  %v\n", e)
				}
				return fmt.Errorf("%d error(s)", len(result.Errors))
			}
			fmt.Printf("%d rules OK (%s)\n", len(result.Rules), result.RuleDir)
			return nil
		},
	}
	lint.Flags().StringVar(&policyDir, "policy-dir", "", "Policy directory (default from config)")

	reload := &cobra.Command{
		Use:   "reload",
		Short: "Reload policies in the running supervisor",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolvePolicyDir(policyDir)
			if err != nil {
				return err
			}
			result := policy.Lint(dir)
			if !result.Ok() {
				for _, e := range result.Errors {
					fmt.Fprintf(os.Stderr, "  %v\n", e)
				}
				return fmt.Errorf("lint failed, not reloading")
			}
			resp, err := rpc.Call(rpc.Request{Command: rpc.CmdReload})
			if err != nil {
				return err
			}
			var r rpc.ReloadResponse
			if err := json.Unmarshal(resp, &r); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}
			if !r.OK {
				return fmt.Errorf("reload failed: %s", r.Error)
			}
			fmt.Println("policy reloaded")
			return nil
		},
	}
	reload.Flags().StringVar(&policyDir, "policy-dir", "", "Policy directory (default from config)")

	var evalJSON bool
	var evalPid int
	var evalCtx policy.EvalContext

	eval := &cobra.Command{
		Use:   "eval <action> <path|tcp:HOST:PORT|unix:PATH>",
		Short: "Show which rule decides and why",
		Long: "Show which rule decides and why.\n\n" +
			"The path is canonicalized first, the same way the supervisor does it, because\n" +
			"that is the path the rules are matched against. Evaluating the path as typed\n" +
			"can name a different rule, or the opposite verdict, when a symlink is involved.\n\n" +
			"Rules reading process or syscall context are reported as [not tested] unless\n" +
			"that context is supplied. Use --exe, --comm, --cwd, --ancestors and --syscall\n" +
			"to describe a hypothetical caller. Supplied values are normalized the way the\n" +
			"kernel would report them, so the answer matches what the runtime would decide.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, ok := policy.ParseAction(args[0])
			if !ok {
				return fmt.Errorf("unknown action %q", args[0])
			}
			ev, err := policy.ParseTarget(action, args[1])
			if err != nil {
				return err
			}
			if ev.Path != "" {
				ev.Path, err = canonicalizeEvalPath(ev.Path, evalPid)
				if err != nil {
					return err
				}
			}
			if err := evalCtx.Apply(ev); err != nil {
				return err
			}
			dir, err := resolvePolicyDir(policyDir)
			if err != nil {
				return err
			}
			result := policy.Lint(dir)
			if !result.Ok() {
				for _, e := range result.Errors {
					fmt.Fprintf(os.Stderr, "  %v\n", e)
				}
				return fmt.Errorf("policy errors")
			}
			evaluated := policy.Eval(result.Rules, ev)
			if evalJSON {
				out, err := policy.FormatEvalJSON(evaluated)
				if err != nil {
					return err
				}
				fmt.Print(out)
				return nil
			}
			fmt.Print(policy.FormatEval(evaluated))
			return nil
		},
	}
	eval.Flags().StringVar(&policyDir, "policy-dir", "", "Policy directory (default from config)")
	eval.Flags().BoolVar(&evalJSON, "json", false, "Output machine-readable JSON")
	eval.Flags().IntVar(&evalPid, "pid", 0, "Resolve /proc/self and /dev/fd as this pid (default: this process)")
	eval.Flags().StringVar(&evalCtx.Exe, "exe", "", "Hypothetical process.exe, absolute (symlinks are resolved, as /proc/<pid>/exe reports it)")
	eval.Flags().StringVar(&evalCtx.Comm, "comm", "", "Hypothetical process.comm (basename, truncated to 15 bytes as the kernel does; defaults to the --exe basename)")
	eval.Flags().StringVar(&evalCtx.Cwd, "cwd", "", "Hypothetical process.cwd, absolute (symlinks are resolved)")
	eval.Flags().StringSliceVar(&evalCtx.Ancestors, "ancestors", nil, "Hypothetical ancestor exe basenames, immediate parent first; what startedBy() reads")
	eval.Flags().StringVar(&evalCtx.Syscall, "syscall", "", "Hypothetical syscall name, e.g. openat2 (several syscalls share one action)")

	explain := &cobra.Command{
		Use:   "explain",
		Short: "Show schema documentation for rules and events",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(policy.FormatExplain(policy.ExplainRule()))
			fmt.Println("────────────────────────────────────────")
			fmt.Println()
			fmt.Print(policy.FormatExplain(policy.ExplainEvent()))
			return nil
		},
	}

	cmd.AddCommand(lint, reload, eval, explain)
	return cmd
}

// resolvePolicyDir returns the policy directory from a flag override or from
// config. Returns an error if config.Load fails, instead of silently falling
// back to the current directory: linting "." as if it were the policy dir
// produces confusing parse errors from whatever project happens to be the
// cwd (see #config.yaml unreadable from inside its own sandbox).
func resolvePolicyDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("loading config to find policy dir: %w", err)
	}
	return cfg.PolicyDir, nil
}

// canonicalizeEvalPath puts an eval target through the same resolution the
// supervisor applies before matching rules: absolute, then symlinks and procfs
// magic links resolved.
//
// This is the one runtime step that is safe to reproduce here. eval runs on the
// same machine in the same mount namespace, so CanonicalizePathForPid gives the
// same answer it gives on the syscall path. Syscall decoding and dirfd/cwd
// resolution are not reproducible and are deliberately not attempted.
//
// pid selects whose /proc/self and /dev/fd are meant. Zero means this process,
// which is the honest default for a question asked from a shell.
func canonicalizeEvalPath(path string, pid int) (string, error) {
	if pid < 0 {
		return "", fmt.Errorf("invalid --pid %d", pid)
	}
	if pid == 0 {
		pid = os.Getpid()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", path, err)
	}
	return supervisor.CanonicalizePathForPid(abs, uint32(pid)), nil
}
