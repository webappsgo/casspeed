package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpListsProjectCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --help exit code = %d, stderr=%q", code, stderr.String())
	}
	for _, command := range []string{"test", "health", "history", "share", "login"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help output does not list %q: %s", command, stdout.String())
		}
	}
}

func TestRunRejectsInvalidOutputFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--output", "yaml", "health"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid output exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "output must be json or table") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}
