// Command gravelpit is the CLI entry point for the seccomp-based sandbox supervisor.
package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/tsaarni/gravelpit/internal/sandbox"
)

func main() {
	// When "gravelpit run" starts a sandbox, it re-executes this binary once to
	// set up seccomp in the child before exec'ing the target command. The
	// re-executed copy takes this branch and never returns.
	if sandbox.IsSandboxChild() {
		sandbox.RunSandboxChild()
	}

	root := &cobra.Command{
		Use:          "gravelpit",
		Short:        "Seccomp-based sandbox supervisor for LLM agents",
		SilenceUsage: true,
	}

	root.AddCommand(
		cmdRun(),
		cmdPolicy(),
		cmdConfig(),
		cmdStatus(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
