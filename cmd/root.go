package cmd

import (
	"fmt"
	"os"
	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/hunter"
	"rmm-hunter/internal/tui"

	"github.com/spf13/cobra"
)

var (
	excludeRMMs []string
	outputFile  string
	webUI       bool
	cliUI       bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rmm-hunter",
	Short: "RMM-Hunter - Detect and eliminate Remote Monitoring and Management software",
	Long: `RMM-Hunter is a tool designed to detect and eliminate Remote Monitoring 
and Management (RMM) software on Windows systems. It can hunt for suspicious 
processes, services, binaries, and network connections associated with RMM tools.`,
	Version: "1.0.0",
}

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Hunt for RMM software on the system",
	Long: `Hunt mode scans the system for signs of RMM software including:
- Suspicious Processes
- Suspicious Autoruns
- Services
- Binaries and Executables
- Directories
- Processes
- Outbound Network Connections
- Scheduled Tasks
- Registry Entries`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting RMM Hunt...")
		runHunt()
	},
}

// eliminateCmd represents the eliminate command
var eliminateCmd = &cobra.Command{
	Use:   "eliminate",
	Short: "Eliminate Sus software based on hunt results",
	Long: `Eliminate mode removes detected Sus software from the system.
Requires a JSON input file containing hunt results to determine what to remove.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting Elimination UI...")
		runEliminate()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(huntCmd)
	rootCmd.AddCommand(eliminateCmd)

	// Global flags
	rootCmd.PersistentFlags().StringSliceVar(&excludeRMMs, "exclude", []string{},
		"Comma-separated list of Sus names to exclude from detection (optional)")

	// Hunt command flags
	huntCmd.Flags().StringSliceVar(&excludeRMMs, "exclude", []string{},
		"Comma-separated list of Sus names to exclude from hunt")
	huntCmd.Flags().StringVarP(&outputFile, "output", "o", "suspicious-hunter.json",
		"Output file to write hunt results (optional) Default: suspicious-hunter.json")

	// Eliminate command flags
	eliminateCmd.Flags().BoolVarP(&webUI, "web", "w", false,
		"Use web UI instead of TUI (optional)")
	eliminateCmd.Flags().BoolVarP(&cliUI, "cli", "c", false,
		"Use CLI UI instead of TUI (optional)")

	// Mark web and cli flags as mutually exclusive
	eliminateCmd.MarkFlagsMutuallyExclusive("web", "cli")

	// Mark one of web or cli as required
	eliminateCmd.MarkFlagsOneRequired("web", "cli")
}

func runHunt() {
	if len(excludeRMMs) > 0 {
		fmt.Printf("Excluding RMMs: %v\n", excludeRMMs)
	}

	hunter.Start(pkg.RunOptions{
		ExcludeRMMs: excludeRMMs,
	})

}

func runEliminate() {
	if webUI {
		// Launch the web UI for elimination flow
		// TODO: Launch web UI
		fmt.Println("Web UI not implemented yet")
		return
	} else if cliUI {
		// Launch the TUI for elimination flow
		if err := tui.RunEliminateUI(); err != nil {
			fmt.Printf("[-] TUI error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("No UI specified")
		os.Exit(1)
	}
}
