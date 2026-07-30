package tor

import (
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
	// Valid prefix: a-z and 2-7 only
	err := svc.GenerateVanityAddress("test2")
	// Current implementation always returns error (requires external tool).
	if err == nil {
		t.Log("GenerateVanityAddress succeeded unexpectedly — tool available")
	}
}
