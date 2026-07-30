package logging

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- New() tests ---------------------------------------------------------

func TestNew_CreatesLogFiles(t *testing.T) {
	dir := t.TempDir()
	logger, err := New(dir)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// All five log files should have been created.
	for _, name := range []string{"access.log", "server.log", "error.log", "audit.log", "security.log"} {
		path := filepath.Join(dir, name)
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			t.Errorf("log file %q not created", name)
		}
	}
}

func TestNew_SubDirCreated(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "logs", "app")
	logger, err := New(subDir)
	if err != nil {
		t.Fatalf("New with nested dir error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNew_LoggersNotNil(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if l.Access == nil {
		t.Error("Access logger is nil")
	}
	if l.Server == nil {
		t.Error("Server logger is nil")
	}
	if l.Error == nil {
		t.Error("Error logger is nil")
	}
	if l.Audit == nil {
		t.Error("Audit logger is nil")
	}
	if l.Security == nil {
		t.Error("Security logger is nil")
	}
}

// ---- AuditLog tests ------------------------------------------------------

func TestAuditLog_WritesEntry(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Should not panic or error.
	l.AuditLog("user.login", map[string]interface{}{
		"username": "alice",
		"ip":       "127.0.0.1",
	})

	// Verify file has content.
	data, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit.log should not be empty after AuditLog call")
	}
}

func TestAuditLog_EmptyData(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	// Must not panic with nil/empty data.
	l.AuditLog("system.start", nil)
	l.AuditLog("system.stop", map[string]interface{}{})
}
