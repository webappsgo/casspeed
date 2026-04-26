package main

import (
"flag"
"fmt"
"os"
"path/filepath"

"github.com/casapps/casspeed/src/client/tui"
"golang.org/x/term"
)

var (
Version   = "dev"
CommitID  = "unknown"
BuildDate = "unknown"
)

func main() {
binaryName := filepath.Base(os.Args[0])

var (
showHelp    bool
showVersion bool
serverURL   string
)

flag.BoolVar(&showHelp, "help", false, "Show help")
flag.BoolVar(&showHelp, "h", false, "Show help (short)")
flag.BoolVar(&showVersion, "version", false, "Show version")
flag.BoolVar(&showVersion, "v", false, "Show version (short)")
flag.StringVar(&serverURL, "server", "http://localhost:64580", "Server URL")

flag.Usage = func() {
fmt.Printf(`%s - casspeed CLI Client

Usage: %s [options]

Options:
  -h, --help              Show this help
  -v, --version           Show version
  --server URL            Server URL (default: http://localhost:64580)

TUI Mode (automatic when no command):
  %s                     Launch interactive TUI
  %s --server URL        Launch TUI with custom server

Examples:
  %s
  %s --server https://speed.example.com

`, binaryName, binaryName, binaryName, binaryName, binaryName, binaryName)
}

flag.Parse()

if showHelp {
flag.Usage()
os.Exit(0)
}

if showVersion {
fmt.Printf("%s v%s (%s) built %s\n", binaryName, Version, CommitID, BuildDate)
os.Exit(0)
}

// Auto-detect TUI mode: interactive terminal + no commands
if term.IsTerminal(int(os.Stdout.Fd())) && flag.NArg() == 0 {
if err := tui.Run(serverURL); err != nil {
fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
os.Exit(1)
}
return
}

// CLI mode for scripting (commands not implemented yet)
fmt.Println("CLI mode not yet implemented. Use TUI mode (run without arguments).")
}
