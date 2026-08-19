// cmd_status.go implements the "status" subcommand that queries runtime statistics from the supervisor.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/tsaarni/gravelpit/internal/rpc"
)

func cmdStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show sandbox runtime statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := rpc.Call(rpc.Request{Command: rpc.CmdSummary})
			if err != nil {
				return err
			}
			var s rpc.SummaryResponse
			if err := json.Unmarshal(resp, &s); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}
			printSummary(&s)
			return nil
		},
	}

	recent := &cobra.Command{
		Use:   "recent",
		Short: "Show recent intercepted syscalls",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := rpc.Call(rpc.Request{Command: rpc.CmdRecent})
			if err != nil {
				return err
			}
			var r rpc.RecentResponse
			if err := json.Unmarshal(resp, &r); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}
			printRecent(&r)
			return nil
		},
	}

	denies := &cobra.Command{
		Use:   "denies",
		Short: "Show recent denied syscalls",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := rpc.Call(rpc.Request{Command: rpc.CmdDenies})
			if err != nil {
				return err
			}
			var r rpc.RecentResponse
			if err := json.Unmarshal(resp, &r); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}
			printRecent(&r)
			return nil
		},
	}

	cmd.AddCommand(recent)
	cmd.AddCommand(denies)
	return cmd
}

func printSummary(s *rpc.SummaryResponse) {
	writeSummary(os.Stdout, s)
}

// writeSummary renders the summary. Split from printSummary so the layout can be
// tested without capturing stdout.
func writeSummary(out io.Writer, s *rpc.SummaryResponse) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "UPTIME\tREQUESTS\tALLOWED\tDENIED\tRELOADS\n")
	fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\n",
		s.Uptime, s.TotalRequests, s.TotalAllows, s.TotalDenies, s.ReloadCount)
	w.Flush()

	// One row per in-memory table. Only the decision cache has hit counters.
	if len(s.Caches) > 0 {
		fmt.Fprintln(out)
		w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "CACHE\tENTRIES\tMEMORY\tHITS\tMISSES\tHIT RATE\n")
		for _, c := range s.Caches {
			hits, misses, hitRate := "-", "-", "-"
			if c.HitsTracked {
				hits = strconv.FormatInt(c.Hits, 10)
				misses = strconv.FormatInt(c.Misses, 10)
				if total := c.Hits + c.Misses; total > 0 {
					hitRate = fmt.Sprintf("%.1f%%", float64(c.Hits)/float64(total)*100)
				}
			}
			fmt.Fprintf(w, "%s\t%d/%d\t%s\t%s\t%s\t%s\n",
				c.Name, c.Entries, c.Capacity, humanize.IBytes(uint64(c.Bytes)),
				hits, misses, hitRate)
		}
		w.Flush()
	}

	if len(s.ActionAllows) > 0 || len(s.ActionDenies) > 0 {
		fmt.Fprintln(out)
		w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ACTION\tALLOW\tDENY\n")
		actions := collectActions(s.ActionAllows, s.ActionDenies)
		for _, a := range actions {
			allows := s.ActionAllows[a]
			denies := s.ActionDenies[a]
			if allows == 0 && denies == 0 {
				continue
			}
			fmt.Fprintf(w, "%s\t%d\t%d\n", a, allows, denies)
		}
		w.Flush()
	}
}

func printRecent(r *rpc.RecentResponse) {
	if len(r.Entries) == 0 {
		fmt.Println("No entries recorded.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "AGE\tVERDICT\tACTION\tRULE\tPATH\n")
	for _, e := range r.Entries {
		age := formatAge(time.Since(e.Timestamp))
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", age, e.Verdict, e.Action, e.Rule, e.Path)
	}
	w.Flush()
}

// formatAge formats a duration into a short human-readable string.
func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// collectActions returns the union of action keys from both maps in canonical order.
func collectActions(a, b map[string]int64) []string {
	seen := make(map[string]bool)
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	order := []string{"read", "write", "delete", "metadata", "exec", "connect"}
	var result []string
	for _, o := range order {
		if seen[o] {
			result = append(result, o)
			delete(seen, o)
		}
	}
	for k := range seen {
		result = append(result, k)
	}
	var filtered []string
	for _, s := range result {
		if strings.TrimSpace(s) != "" {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
