package tor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- NewService tests ----------------------------------------------------

func TestNewService_NotNil(t *testing.T) {
	cfg := &Config{
		Enabled:    false,
		HiddenPort: 80,
	}
	svc := NewService(cfg)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
}

func TestNewService_NotRunning(t *testing.T) {
	svc := NewService(&Config{})
	if svc.IsRunning() {
		t.Error("new service should not be running")
	}
}

// ---- Start when disabled ------------------------------------------------

func TestStart_WhenDisabled(t *testing.T) {
	svc := NewService(&Config{Enabled: false})
	if err := svc.Start(); err != nil {
		t.Errorf("Start with Enabled=false should return nil, got: %v", err)
	}
	if svc.IsRunning() {
		t.Error("should not be running when disabled")
	}
}

// ---- GetOnionAddress tests -----------------------------------------------

func TestGetOnionAddress_InitiallyEmpty(t *testing.T) {
	svc := NewService(&Config{})
	if got := svc.GetOnionAddress(); got != "" {
		t.Errorf("onion address should be empty initially, got %q", got)
	}
}

// ---- GetListener tests ---------------------------------------------------

func TestGetListener_InitiallyNil(t *testing.T) {
	svc := NewService(&Config{})
	if got := svc.GetListener(); got != nil {
		t.Errorf("listener should be nil initially, got %v", got)
	}
}

// ---- Status tests -------------------------------------------------------

func TestStatus_WhenNotRunning(t *testing.T) {
	svc := NewService(&Config{Enabled: true})
	status := svc.Status()

	if enabled, ok := status["enabled"].(bool); !ok || !enabled {
		t.Errorf("status[enabled] = %v, want true", status["enabled"])
	}
	if running, ok := status["running"].(bool); !ok || running {
		t.Errorf("status[running] = %v, want false", status["running"])
	}
}

// ---- GenerateVanityAddress tests ----------------------------------------

func TestGenerateVanityAddress_EmptyPrefix(t *testing.T) {
	svc := NewService(&Config{})
	err := svc.GenerateVanityAddress("")
	if err == nil {
		t.Error("expected error for empty prefix")
	}
}

func TestGenerateVanityAddress_InvalidChars(t *testing.T) {
	svc := NewService(&Config{})
	err := svc.GenerateVanityAddress("abc!123")
	if err == nil {
		t.Error("expected error for invalid characters in prefix")
	}
}

func TestGenerateVanityAddress_ValidPrefix(t *testing.T) {
	svc := NewService(&Config{})
	// Valid base32 input passes validation, then reports that the external
	// vanity-generation tool is not part of this service.
	err := svc.GenerateVanityAddress("TeSt27")
	if err == nil || !strings.Contains(err.Error(), "requires external tool mkp224o") {
		t.Fatalf("GenerateVanityAddress(valid prefix) error = %v, want external-tool guidance", err)
	}
}

func TestGenerateVanityAddressRejectsBase32Boundaries(t *testing.T) {
	svc := NewService(&Config{})
	for _, prefix := range []string{"a0", "z8", "-a"} {
		if err := svc.GenerateVanityAddress(prefix); err == nil || !strings.Contains(err.Error(), "invalid prefix character") {
			t.Errorf("GenerateVanityAddress(%q) error = %v, want invalid-character error", prefix, err)
		}
	}
}

func TestStopWhenNotRunning(t *testing.T) {
	svc := NewService(&Config{})
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop on a stopped service: %v", err)
	}
	if svc.IsRunning() {
		t.Error("Stop should leave a stopped service stopped")
	}
}

func TestParseHiddenServiceHostname(t *testing.T) {
	dir := t.TempDir()
	hostnamePath := filepath.Join(dir, "hidden_service", "hostname")
	if err := os.MkdirAll(filepath.Dir(hostnamePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostnamePath, []byte("exampleonionaddress.onion\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseHiddenServiceHostname(dir)
	if err != nil {
		t.Fatalf("ParseHiddenServiceHostname: %v", err)
	}
	if got != "exampleonionaddress.onion" {
		t.Errorf("hostname = %q, want trimmed hostname", got)
	}
	if _, err := ParseHiddenServiceHostname(t.TempDir()); err == nil {
		t.Error("missing hostname file should return an error")
	}
}

func TestFindInPathRequiresExecutable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	program := filepath.Join(dir, "tor")
	if err := os.WriteFile(program, []byte("fake tor"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := findInPath("tor"); err == nil {
		t.Fatal("findInPath should reject a non-executable file")
	}
	if err := os.Chmod(program, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := findInPath("tor")
	if err != nil {
		t.Fatalf("findInPath executable: %v", err)
	}
	if got != program {
		t.Errorf("findInPath = %q, want %q", got, program)
	}
}
