package pid

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// ---- CheckPIDFile tests --------------------------------------------------

func TestCheckPIDFile_NonExistent(t *testing.T) {
	running, pid, err := CheckPIDFile("/tmp/casspeed_test_nonexistent_pid_XXXXX.pid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Error("should not be running when pid file does not exist")
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0", pid)
	}
}

func TestCheckPIDFile_CorruptContent(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(pidPath, []byte("not-a-number"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	running, pid, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Error("should not be running for corrupt PID content")
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0", pid)
	}
	// Corrupt file should have been removed.
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Error("corrupt PID file should have been removed")
	}
}

func TestCheckPIDFile_StalePID(t *testing.T) {
	// PID 999999999 is almost certainly not a running process.
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "stale.pid")
	if err := os.WriteFile(pidPath, []byte("999999999"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	running, _, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Error("stale PID (non-existent process) should not be reported as running")
	}
	// Stale PID file should have been removed.
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Error("stale PID file should have been removed")
	}
}

// ---- WritePIDFile tests --------------------------------------------------

func TestWritePIDFile_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "sub", "test.pid")

	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("WritePIDFile error: %v", err)
	}

	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	written, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatalf("pid file content %q not a number", string(data))
	}
	if written != os.Getpid() {
		t.Errorf("pid file contains %d, want %d", written, os.Getpid())
	}
}

func TestWritePIDFile_IdempotentAfterRemove(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "test.pid")

	// First write should succeed.
	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("first WritePIDFile: %v", err)
	}

	// Remove the file manually to simulate clean shutdown.
	if err := RemovePIDFile(pidPath); err != nil {
		t.Fatalf("RemovePIDFile: %v", err)
	}

	// Second write should also succeed now.
	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("second WritePIDFile after remove: %v", err)
	}
}

// ---- RemovePIDFile tests -------------------------------------------------

func TestRemovePIDFile_RemovesExistingFile(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "test.pid")
	os.WriteFile(pidPath, []byte("1"), 0644)

	if err := RemovePIDFile(pidPath); err != nil {
		t.Fatalf("RemovePIDFile error: %v", err)
	}
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Error("PID file should have been removed")
	}
}

func TestRemovePIDFile_NonExistentReturnsError(t *testing.T) {
	err := RemovePIDFile("/tmp/casspeed_test_totally_missing_XXXXX.pid")
	if err == nil {
		t.Error("expected error when removing non-existent file")
	}
}
