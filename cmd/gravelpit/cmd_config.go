// cmd_config.go implements the "config explain" and "config show" subcommands.
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tsaarni/gravelpit/internal/config"
)

func cmdConfig() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration management commands"}

	explain := &cobra.Command{
		Use:   "explain",
		Short: "Show config file schema documentation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(config.FormatExplainConfig(config.ExplainConfig()))
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "Show effective merged configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := config.Show()
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}

	cmd.AddCommand(explain, show)
	return cmd
}
