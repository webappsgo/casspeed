package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/casapps/casspeed/src/client/tui"
	"github.com/casapps/casspeed/src/common/i18n"
	"golang.org/x/term"
)

var (
	Version   = "dev"
	CommitID  = "unknown"
	BuildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	binaryName := filepath.Base(os.Args[0])
	flags := flag.NewFlagSet(binaryName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", "http://localhost:64580", "Server URL")
	language := flags.String("lang", "", "Language for output (default: auto)")
	token := flags.String("token", "", "API token")
	tokenFile := flags.String("token-file", "", "Read API token from file")
	output := flags.String("output", "table", "Output format: json or table")
	update := flags.String("update", "", "Check for updates or request an update: check, yes")
	showVersion := false
	flags.BoolVar(&showVersion, "version", false, "Show version")
	flags.BoolVar(&showVersion, "v", false, "Show version (short)")
	showHelp := false
	flags.BoolVar(&showHelp, "help", false, "Show help")
	flags.BoolVar(&showHelp, "h", false, "Show help (short)")
	flags.Usage = func() {
		fmt.Fprintf(stdout, `%s - CasSpeed CLI Client

Usage: %s [options] [command]

Commands:
  test                 Run a speed test (default in non-interactive mode)
  health               Show server health
  history              List your saved test results
  share TEST_ID        Create a public share link for a saved result
  login                Save an API token for later commands

Options:
  -h, --help           Show this help
  -v, --version        Show version
  --server URL         Server URL
  --lang CODE          Language for output (en, es, fr, de, it, ar)
  --token TOKEN        API token
  --token-file FILE    Read API token from file
  --output FORMAT      json or table
  --update ACTION      check for a CLI update or request one (check, yes)

`, binaryName, binaryName)
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if showHelp {
		flags.Usage()
		return 0
	}
	if showVersion {
		fmt.Fprintf(stdout, "%s v%s (%s) built %s\n", binaryName, Version, CommitID, BuildDate)
		return 0
	}
	resolvedLanguage := *language
	if resolvedLanguage == "" {
		resolvedLanguage = os.Getenv("LC_ALL")
	}
	if resolvedLanguage == "" {
		resolvedLanguage = os.Getenv("LANG")
	}
	resolvedLanguage = i18n.Normalize(resolvedLanguage)
	commandArgs := flags.Args()
	if *output != "json" && *output != "table" {
		fmt.Fprintln(stderr, "error: output must be json or table")
		return 2
	}
	resolvedToken, err := resolveToken(*token, *tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *update != "" && *update != "check" && *update != "yes" {
		fmt.Fprintln(stderr, "error: --update must be check or yes")
		return 2
	}
	if *update == "check" && len(commandArgs) > 0 {
		fmt.Fprintln(stderr, "error: --update check cannot be combined with a command")
		return 2
	}
	updateCode, updated := checkAndUpdateCLI(*serverURL, resolvedToken, *update, os.Args, os.Stdin, stdout, stderr)
	if *update == "check" || updated || updateCode != 0 {
		return updateCode
	}
	if len(commandArgs) == 0 && term.IsTerminal(int(os.Stdout.Fd())) {
		if err := tui.Run(*serverURL); err != nil {
			fmt.Fprintf(stderr, "TUI error: %v\n", err)
			return 1
		}
		return 0
	}
	command := "test"
	if len(commandArgs) > 0 {
		command = commandArgs[0]
		commandArgs = commandArgs[1:]
	}
	return execute(command, commandArgs, clientOptions{serverURL: *serverURL, token: resolvedToken, output: *output, language: resolvedLanguage}, stdout, stderr)
}
