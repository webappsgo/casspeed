package i2p

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func validTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ConfigDir = filepath.Join(t.TempDir(), "config")
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.LogDir = filepath.Join(t.TempDir(), "logs")
	return cfg
}

func TestDefaultConfigAndManagerLifecycle(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled || cfg.SAMAddress != "127.0.0.1:7656" || cfg.VirtualPort != 80 || cfg.BootstrapTimeout != 300*time.Second {
		t.Fatalf("unexpected I2P defaults: %#v", cfg)
	}
	manager := NewManager(context.Background(), cfg)
	if state := manager.State(); state.Status != "disabled" || state.Provider != ProviderNone || manager.EepsiteAddress() != "" {
		t.Fatalf("unexpected stopped manager state: %#v", state)
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}

func TestValidateConfig(t *testing.T) {
	valid := validTestConfig(t)
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"malformed SAM address", func(cfg *Config) { cfg.SAMAddress = "router" }},
		{"invalid virtual port", func(cfg *Config) { cfg.VirtualPort = 65536 }},
		{"invalid tunnel length", func(cfg *Config) { cfg.InboundLength = 8 }},
		{"invalid tunnel quantity", func(cfg *Config) { cfg.OutboundQuantity = 0 }},
		{"invalid signature", func(cfg *Config) { cfg.SignatureType = 1 }},
		{"short timeout", func(cfg *Config) { cfg.BootstrapTimeout = 29 * time.Second }},
		{"missing directory", func(cfg *Config) { cfg.DataDir = "" }},
		{"missing binary", func(cfg *Config) { cfg.Binary = filepath.Join(t.TempDir(), "missing-i2pd") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.edit(&candidate)
			if err := ValidateConfig(candidate); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestManagerUpdateAndRegenerateValidation(t *testing.T) {
	manager := NewManager(context.Background(), DefaultConfig())
	if _, err := manager.RegenerateAddress(context.Background()); err == nil || err.Error() != "I2P is disabled" {
		t.Fatalf("disabled regenerate error = %v", err)
	}
	cfg := validTestConfig(t)
	manager = NewManager(context.Background(), cfg)
	if _, err := manager.RegenerateAddress(context.Background()); err == nil || err.Error() != "I2P manager has not been started" {
		t.Fatalf("unstarted regenerate error = %v", err)
	}
	invalid := cfg
	invalid.VirtualPort = 0
	if err := manager.UpdateConfig(invalid); err == nil {
		t.Fatal("invalid update was accepted")
	}
	if err := manager.UpdateConfig(DefaultConfig()); err != nil {
		t.Fatalf("disable update: %v", err)
	}
	if state := manager.State(); state.Status != "disabled" || state.Enabled {
		t.Fatalf("updated state = %#v", state)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerPublishesProviderStartupFailure(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Binary = filepath.Join(t.TempDir(), "missing-i2pd")
	manager := NewManager(context.Background(), cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		state := manager.State()
		if state.Status == "error" {
			if !state.Enabled || state.Error == "" || strings.Contains(state.Error, "missing-i2pd") {
				t.Fatalf("startup failure state = %#v", state)
			}
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("manager did not publish startup failure; state=%#v", state)
		}
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStartServiceValidationAndDisabled(t *testing.T) {
	if _, err := StartService(context.Background(), DefaultConfig()); err == nil || err.Error() != "I2P disabled" {
		t.Fatalf("disabled start error = %v", err)
	}
	cfg := validTestConfig(t)
	cfg.VirtualPort = 0
	if _, err := StartService(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "virtual port") {
		t.Fatalf("invalid start error = %v", err)
	}
}

func TestEnsureDirsAndServiceClose(t *testing.T) {
	cfg := validTestConfig(t)
	if err := ensureDirs(cfg); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(cfg.ConfigDir, "i2p"), filepath.Join(cfg.DataDir, "i2p"), filepath.Join(cfg.DataDir, "i2p", "site"), cfg.LogDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("%s permissions = %04o, want 0700", path, info.Mode().Perm())
		}
	}
	listener, err := allocateBackendListener()
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{listener: listener, state: State{Status: "running"}, done: make(chan struct{})}
	if service.State().Status != "running" || service.BackendListener() != listener {
		t.Fatal("service accessors returned unexpected state")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); err == nil {
		t.Fatal("closed backend listener still accepts connections")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("repeated service close: %v", err)
	}
}

func TestSafeErrorRedactsSessionSecrets(t *testing.T) {
	if got := safeError(ErrNoProvider{Address: "secret"}); got != "no I2P provider available" {
		t.Fatalf("no-provider error = %q", got)
	}
	if got := safeError(errors.New("SAM failed DESTINATION=private")); got != "I2P startup failed" {
		t.Fatalf("secret error = %q", got)
	}
	if got := safeError(errors.New("ordinary startup failure")); got != "ordinary startup failure" {
		t.Fatalf("ordinary error = %q", got)
	}
}

func TestI2PDConfigAndPrivateFilePermissions(t *testing.T) {
	contents := i2pdConfig(7656, "logs\\private\nname\r.log")
	if !strings.Contains(contents, "port = 7656") || !strings.Contains(contents, "logfile = logs\\\\privatename.log") || strings.Contains(contents, "\r") {
		t.Fatalf("i2pd config did not safely encode the log path: %q", contents)
	}
	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != "secret" {
		t.Fatalf("private file contents = %q, %v", stored, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file mode = %v, %v", info, err)
	}
	if err := writePrivateFile(filepath.Join(t.TempDir(), "missing", "key"), []byte("x")); err == nil {
		t.Fatal("private file creation with a missing parent unexpectedly succeeded")
	}
}

func TestUnusedPortSelectsAnAvailableLoopbackPortInRequiredRange(t *testing.T) {
	port, err := unusedPort()
	if err != nil {
		t.Fatal(err)
	}
	if port < 64000 || port > 64999 {
		t.Fatalf("SAM port = %d, want 64000-64999", port)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("selected SAM port %d was not available: %v", port, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
