// Command garmd is the garm daemon: a policy-enforcing proxy between an agent
// and the tools it may call.
//
// It is not the command line tool. That is garm, in a separate repository, and
// nothing here depends on it beyond the contract language they share.
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/garm-ai/garmd/internal/catalogue"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "garmd",
		Short: "The governed tool plane",
		Long: "garmd stands between an agent and the tools it may call, and decides\n" +
			"on every call what passes and what the caller is allowed to see of\n" +
			"the answer.\n\n" +
			"It serves the tools a catalogue declares, not the tools it was built\n" +
			"with. Adding a tool is a catalogue rebuild and a restart.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.AddCommand(newVersionCmd(), newServeCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version())
			return nil
		},
	}
}

// version reports the module version the Go toolchain stamped: a tag for an
// installed build, "(devel)" from a working tree.
//
// Once a catalogue can be loaded this stops being the whole answer. Identity
// is the pair (binary version, catalogue digest), and a garmd that reports
// only half of it cannot answer which tools it is serving.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "dev"
	}
	return info.Main.Version
}

// bytesHuman keeps a startup line readable. Binary units, because the numbers
// it prints are memory and file sizes rather than anything a disk vendor
// measured.
func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func newServeCmd() *cobra.Command {
	var cataloguePath string
	var maxTools int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the tool plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, cataloguePath, maxTools)
		},
	}
	cmd.Flags().StringVar(&cataloguePath, "catalogue", "",
		"Path to the catalogue artifact this process serves")
	cmd.Flags().IntVar(&maxTools, "max-tools", 0,
		"Refuse a catalogue declaring more tools than this. 0 means no limit; "+
			"set it to catch a deployment pointed at the wrong catalogue")
	return cmd
}

func runServe(cmd *cobra.Command, path string, maxTools int) error {
	// A tool plane with no catalogue serves nothing. Saying so is better than
	// binding a listener that answers 404 — that is the failure nothing
	// downstream can detect.
	if path == "" {
		return fmt.Errorf("--catalogue is required: garmd serves the tools an artifact " +
			"declares, and will not bind a listener it has nothing to serve on")
	}

	store := catalogue.NewStore(catalogue.Options{MaxTools: maxTools})
	cat, err := store.Reload(cmd.Context(), catalogue.FileSource{Path: path})
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	// Identity is the PAIR. A build number alone stopped answering "which
	// tools is this process serving" the moment the catalogue left the binary.
	fmt.Fprintf(out, "garmd %s\n", version())
	fmt.Fprintf(out, "catalogue %s\n", cat.Digest)
	if p := cat.Provenance; p != nil {
		fmt.Fprintf(out, "  built by %s (%s)\n", p.GetProducer(), p.GetCompiler())
	}
	fmt.Fprintf(out, "  annotation schema v%d, %d compartment(s), %d tool set(s)\n",
		cat.SchemaVersion, len(cat.Compartments), len(cat.ToolSets))

	// The size line is always printed, limit or not. What it guards against
	// is a deployment pointed at the organisation-wide catalogue rather than
	// its own, and an operator who never sets a limit should still be able to
	// see that happen.
	budget := "no limit set"
	if m := store.MaxTools(); m > 0 {
		budget = fmt.Sprintf("limit %d", m)
	}
	fmt.Fprintf(out, "  %s, %s held, %d tool(s), %s\n",
		bytesHuman(int64(cat.Bytes)), bytesHuman(int64(cat.HeapBytes)), len(cat.Defs), budget)

	fmt.Fprintf(out, "%d tool(s) declared:\n", len(cat.Defs))
	for _, d := range cat.Defs {
		shown := ""
		if d.ClientName != d.Name {
			// Worth saying out loud: a name differing from its declaration is
			// the sort of thing an operator should learn at startup rather
			// than from a confused caller.
			shown = fmt.Sprintf("  (callers see %s)", d.ClientName)
		}
		fmt.Fprintf(out, "  %-44s %s%s\n", d.FQN, d.Verb, shown)
	}

	return fmt.Errorf("no resolver: garmd can load a catalogue but cannot yet route to " +
		"the services that implement it")
}
