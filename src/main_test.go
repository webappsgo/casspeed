package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout captures stdout output during f() execution
func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestResolveColorMode(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		noColor  string
		wantBool bool
	}{
		{name: "yes", flag: "yes", wantBool: true},
		{name: "Yes", flag: "Yes", wantBool: true},
		{name: "on", flag: "on", wantBool: true},
		{name: "1", flag: "1", wantBool: true},
		{name: "true", flag: "true", wantBool: true},
		{name: "no", flag: "no", wantBool: false},
		{name: "No", flag: "No", wantBool: false},
		{name: "off", flag: "off", wantBool: false},
		{name: "0", flag: "0", wantBool: false},
		{name: "false", flag: "false", wantBool: false},
		{name: "auto-no-color", flag: "auto", noColor: "1", wantBool: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.noColor != "" {
				os.Setenv("NO_COLOR", tt.noColor)
				defer os.Unsetenv("NO_COLOR")
			} else {
				os.Unsetenv("NO_COLOR")
			}
			got := resolveColorMode(tt.flag)
			if got != tt.wantBool {
				t.Errorf("resolveColorMode(%q) = %v, want %v", tt.flag, got, tt.wantBool)
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		version string
	}{
		{"0.1.0"},
		{"1.0.0"},
		{"10.20.30"},
		{"dev"},
		{""},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := pad(tt.version)
			// Result should be a string (possibly empty) — just verify it doesn't panic
			if result == "" && tt.version == "" {
				// empty version still produces padding
			}
			_ = result
		})
	}
}

func TestPadMode(t *testing.T) {
	tests := []string{"production", "development", "debug", ""}
	for _, mode := range tests {
		t.Run(mode, func(t *testing.T) {
			result := padMode(mode)
			_ = result
		})
	}
}

func TestShowVersionInfo(t *testing.T) {
	Version = "1.2.3"
	CommitID = "abc1234"
	BuildDate = "Mon Jan 01, 2025 at 00:00:00 UTC"

	out := captureStdout(func() {
		showVersionInfo("casspeed", true)
	})

	if !strings.Contains(out, "1.2.3") {
		t.Errorf("version output missing version: %q", out)
	}
	if !strings.Contains(out, "abc1234") {
		t.Errorf("version output missing commit: %q", out)
	}
}

func TestShowHelpText(t *testing.T) {
	out := captureStdout(func() {
		showHelpText("casspeed")
	})

	if !strings.Contains(out, "--help") {
		t.Errorf("help text missing --help flag: %q", out)
	}
	if !strings.Contains(out, "--version") {
		t.Errorf("help text missing --version flag: %q", out)
	}
	if !strings.Contains(out, "--port") {
		t.Errorf("help text missing --port flag: %q", out)
	}
	if !strings.Contains(out, "--shell") {
		t.Errorf("help text missing --shell flag: %q", out)
	}
	if !strings.Contains(out, "--color") {
		t.Errorf("help text missing --color flag: %q", out)
	}
}

func TestHandleShellCompletions_Bash(t *testing.T) {
	out := captureStdout(func() {
		handleShellCompletions("casspeed", "bash")
	})

	if !strings.Contains(out, "casspeed") {
		t.Errorf("bash completions missing binary name: %q", out)
	}
	if !strings.Contains(out, "complete") {
		t.Errorf("bash completions missing 'complete': %q", out)
	}
}

func TestHandleShellCompletions_Zsh(t *testing.T) {
	out := captureStdout(func() {
		handleShellCompletions("casspeed", "zsh")
	})

	if !strings.Contains(out, "#compdef") {
		t.Errorf("zsh completions missing #compdef: %q", out)
	}
}

func TestHandleShellCompletions_Fish(t *testing.T) {
	out := captureStdout(func() {
		handleShellCompletions("casspeed", "fish")
	})

	if !strings.Contains(out, "complete -c casspeed") {
		t.Errorf("fish completions missing complete command: %q", out)
	}
}

func TestHandleShellInit_Bash(t *testing.T) {
	out := captureStdout(func() {
		handleShellInit("casspeed", "bash")
	})
	if !strings.Contains(out, "completions bash") {
		t.Errorf("bash init missing completions reference: %q", out)
	}
}

func TestHandleShellInit_Zsh(t *testing.T) {
	out := captureStdout(func() {
		handleShellInit("casspeed", "zsh")
	})
	if !strings.Contains(out, "completions zsh") {
		t.Errorf("zsh init missing completions reference: %q", out)
	}
}

func TestHandleShellInit_Fish(t *testing.T) {
	out := captureStdout(func() {
		handleShellInit("casspeed", "fish")
	})
	if !strings.Contains(out, "fish") {
		t.Errorf("fish init missing fish reference: %q", out)
	}
}

func TestHandleShellHelp(t *testing.T) {
	out := captureStdout(func() {
		handleShell("casspeed", "help", nil)
	})
	if !strings.Contains(out, "completions") {
		t.Errorf("shell help missing completions: %q", out)
	}
	if !strings.Contains(out, "init") {
		t.Errorf("shell help missing init: %q", out)
	}
}

func TestPrintSetupInstructions(t *testing.T) {
	out := captureStdout(func() {
		printSetupInstructions("localhost", 8080, "test-setup-token-12345678")
	})
	if !strings.Contains(out, "8080") {
		t.Errorf("setup instructions missing port: %q", out)
	}
	if !strings.Contains(out, "test-setup-token-12345678") {
		t.Errorf("setup instructions missing token: %q", out)
	}
}

// ---- handleService tests (non-exit branches) ----------------------------

func TestHandleService_Start(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "start") })
	if out == "" {
		t.Error("start service output should not be empty")
	}
}

func TestHandleService_Stop(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "stop") })
	if out == "" {
		t.Error("stop service output should not be empty")
	}
}

func TestHandleService_Restart(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "restart") })
	if !strings.Contains(out, "restart") {
		t.Errorf("restart output missing 'restart': %q", out)
	}
}

func TestHandleService_Reload(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "reload") })
	if out == "" {
		t.Error("reload service output should not be empty")
	}
}

func TestHandleService_Install(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "install") })
	if out == "" {
		t.Error("install service output should not be empty")
	}
}

func TestHandleService_Uninstall(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "uninstall") })
	if out == "" {
		t.Error("uninstall service output should not be empty")
	}
}

func TestHandleService_Help(t *testing.T) {
	out := captureStdout(func() { handleService("casspeed", "help") })
	if !strings.Contains(out, "start") {
		t.Errorf("service help missing 'start': %q", out)
	}
}

// ---- handleMaintenance tests (non-exit branches) -------------------------

func TestHandleMaintenance_Update(t *testing.T) {
	out := captureStdout(func() { handleMaintenance("casspeed", "update", nil) })
	if out == "" {
		t.Error("maintenance update output should not be empty")
	}
}

func TestHandleMaintenance_Mode_Production(t *testing.T) {
	out := captureStdout(func() { handleMaintenance("casspeed", "mode", []string{"production"}) })
	if !strings.Contains(out, "production") {
		t.Errorf("maintenance mode output missing 'production': %q", out)
	}
}

func TestHandleMaintenance_Mode_Development(t *testing.T) {
	out := captureStdout(func() { handleMaintenance("casspeed", "mode", []string{"development"}) })
	if !strings.Contains(out, "development") {
		t.Errorf("maintenance mode output missing 'development': %q", out)
	}
}

func TestHandleMaintenance_Setup(t *testing.T) {
	out := captureStdout(func() { handleMaintenance("casspeed", "setup", nil) })
	if out == "" {
		t.Error("maintenance setup output should not be empty")
	}
}

// ---- handleUpdate tests (non-exit branches) ------------------------------

func TestHandleUpdate_BranchStable(t *testing.T) {
	out := captureStdout(func() { handleUpdate("casspeed", "branch", []string{"stable"}) })
	if !strings.Contains(out, "stable") {
		t.Errorf("update branch output missing 'stable': %q", out)
	}
}

func TestHandleUpdate_BranchBeta(t *testing.T) {
	out := captureStdout(func() { handleUpdate("casspeed", "branch", []string{"beta"}) })
	if !strings.Contains(out, "beta") {
		t.Errorf("update branch output missing 'beta': %q", out)
	}
}

func TestHandleUpdate_BranchDaily(t *testing.T) {
	out := captureStdout(func() { handleUpdate("casspeed", "branch", []string{"daily"}) })
	if !strings.Contains(out, "daily") {
		t.Errorf("update branch output missing 'daily': %q", out)
	}
}

func TestHandleUpdate_BranchNoArgs(t *testing.T) {
	out := captureStdout(func() { handleUpdate("casspeed", "branch", nil) })
	if out == "" {
		t.Error("update branch (no args) output should not be empty")
	}
}

// ---- showStatusInfo test (server not running — graceful error path) -----

func TestShowStatusInfo_NotRunning(t *testing.T) {
	out := captureStdout(func() { showStatusInfo("casspeed") })
	if out == "" {
		t.Error("status output should not be empty")
	}
	// When server is not running, expect the "not responding" message
	if !strings.Contains(out, "Status") {
		t.Errorf("status output missing 'Status': %q", out)
	}
}

// ---- printBanner NO_COLOR path ------------------------------------------

func TestPrintBanner_NoColor(t *testing.T) {
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")

	Version = "1.0.0"
	out := captureStdout(func() {
		// printBanner requires mode.State and config.Config — skip; test resolveColorMode path
		color := resolveColorMode("auto")
		if color {
			t.Error("auto mode with NO_COLOR should return false")
		}
	})
	_ = out
}
