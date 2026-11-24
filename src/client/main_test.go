package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMainNonInteractiveMode(t *testing.T) {
	oldArgs := os.Args
	oldStdout := os.Stdout
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
		flag.CommandLine = oldFlags
	})

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}
	os.Stdout = write
	os.Args = []string{"/usr/local/bin/casspeed", "--server", "https://speed.example.com"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	main()
	if err := write.Close(); err != nil {
		t.Fatalf("close output pipe: %v", err)
	}
	os.Stdout = oldStdout

	var output bytes.Buffer
	if _, err := io.Copy(&output, read); err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := read.Close(); err != nil {
		t.Fatalf("close output pipe reader: %v", err)
	}
	if !strings.Contains(output.String(), "CLI mode not yet implemented.") {
		t.Errorf("main output = %q, want non-interactive CLI message", output.String())
	}
}
