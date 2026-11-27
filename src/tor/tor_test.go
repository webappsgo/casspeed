package tor

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cretz/bine/control"
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

func TestManagerLifecycleWithoutTor(t *testing.T) {
	manager := NewManager(context.Background(), Config{}, nil)
	if state := manager.State(); state.Status != "disabled" {
		t.Fatalf("initial state = %#v", state)
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if manager.Listener() != nil || manager.OnionAddress() != "" {
		t.Fatal("disabled manager exposed Tor resources")
	}
	if err := manager.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateConfig(Config{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(); err == nil {
		t.Fatal("closed manager accepted Start")
	}
	if err := manager.Restart(); err == nil {
		t.Fatal("closed manager accepted Restart")
	}
	if _, err := manager.RegenerateAddress(); err == nil {
		t.Fatal("disabled manager regenerated an address")
	}
}

func TestManagerPublishesStartupFailure(t *testing.T) {
	states := make(chan State, 4)
	manager := NewManager(context.Background(), Config{Enabled: true, TorBinary: filepath.Join(t.TempDir(), "missing-tor")}, func(state State) {
		states <- state
	})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		state := manager.State()
		if state.Status == "unavailable" {
			if state.Error == "" || state.Running {
				t.Fatalf("startup failure state = %#v", state)
			}
			break
		}
		select {
		case <-states:
		case <-deadline:
			t.Fatalf("manager did not publish startup failure; state=%#v", state)
		}
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTorConfigValidationAndBandwidth(t *testing.T) {
	valid := Config{
		ConfigDir: t.TempDir(), DataDir: t.TempDir(), LogDir: t.TempDir(),
		StartupTimeout: 30 * time.Second, BootstrapTimeout: 60 * time.Second,
		VirtualPort: 80, MaxCircuits: 8, CircuitTimeout: 60, MaxStreamsPerCircuit: 100,
		NumIntroPoints: 3, BandwidthRate: "1 MB", BandwidthBurst: "2 MB", MaxMonthlyBandwidth: "1 TB",
	}
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid Tor config rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"missing directories", func(cfg *Config) { cfg.DataDir = "" }},
		{"bad contact", func(cfg *Config) { cfg.ContactEmail = "not an email" }},
		{"bad startup timeout", func(cfg *Config) { cfg.StartupTimeout = time.Second }},
		{"bad bootstrap timeout", func(cfg *Config) { cfg.BootstrapTimeout = time.Second }},
		{"bad virtual port", func(cfg *Config) { cfg.VirtualPort = 0 }},
		{"bad circuits", func(cfg *Config) { cfg.MaxCircuits = 0 }},
		{"bad circuit timeout", func(cfg *Config) { cfg.CircuitTimeout = 0 }},
		{"bad streams", func(cfg *Config) { cfg.MaxStreamsPerCircuit = 0 }},
		{"bad intro points", func(cfg *Config) { cfg.NumIntroPoints = 2 }},
		{"bad rate", func(cfg *Config) { cfg.BandwidthRate = "fast" }},
		{"burst below rate", func(cfg *Config) { cfg.BandwidthBurst = "512 KB" }},
		{"bad monthly limit", func(cfg *Config) { cfg.MaxMonthlyBandwidth = "1 MB" }},
		{"missing binary", func(cfg *Config) { cfg.TorBinary = filepath.Join(t.TempDir(), "missing-tor") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.edit(&candidate)
			if err := ValidateConfig(candidate); err == nil {
				t.Fatal("invalid Tor config was accepted")
			}
		})
	}
	if value, err := parseTorBandwidth("3 KB"); err != nil || value != 3072 {
		t.Fatalf("parseTorBandwidth = %d, %v", value, err)
	}
	if _, err := parseTorBandwidth("3 GB"); err == nil {
		t.Fatal("unsupported bandwidth unit was accepted")
	}
}

func TestShouldUseTorAndUnavailableClient(t *testing.T) {
	if ShouldUseTor(nil, nil) {
		t.Fatal("nil config selected Tor")
	}
	cfg := &Config{UseNetwork: true}
	if !ShouldUseTor(cfg, nil) {
		t.Fatal("configured Tor networking was ignored")
	}
	cfg.AllowUserPreference = true
	preference := false
	if ShouldUseTor(cfg, &preference) {
		t.Fatal("explicit false user preference was ignored")
	}
	preference = true
	if !ShouldUseTor(cfg, &preference) {
		t.Fatal("explicit true user preference was ignored")
	}
	client := NewManager(context.Background(), Config{}, nil).GetHTTPClient(true)
	request := httptest.NewRequest("GET", "https://example.com", nil)
	if _, err := client.Transport.RoundTrip(request); err == nil {
		t.Fatal("unavailable Tor client unexpectedly sent a request")
	}
}

func TestGetHTTPClientReusesTorTransport(t *testing.T) {
	svc := &Service{socksAddr: "127.0.0.1:9050"}
	first := svc.GetHTTPClient(true)
	second := svc.GetHTTPClient(true)
	if first != second || first.Transport != second.Transport {
		t.Fatal("Tor HTTP client or transport was recreated")
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

func TestTorRuntimeFileHelpers(t *testing.T) {
	dir := t.TempDir()
	portPath := filepath.Join(dir, "control-port")
	if err := os.WriteFile(portPath, []byte("PORT=127.0.0.1:9051\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if address, err := readTorPortFile(portPath); err != nil || address != "127.0.0.1:9051" {
		t.Fatalf("readTorPortFile() = %q, %v", address, err)
	}
	for _, invalid := range []string{"PORT=0\n", "PORT=127.0.0.1:70000\n", "SOCKS=127.0.0.1:9050\n"} {
		if err := os.WriteFile(portPath, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTorPortFile(portPath); err == nil {
			t.Errorf("readTorPortFile accepted %q", invalid)
		}
	}
	filePath := filepath.Join(dir, "torrc")
	if err := writePrivateFile(filePath, []byte("SocksPort 9050\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file permissions = %v, %v", info, err)
	}
	if err := os.Chmod(filePath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := secureTorFile(filePath); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("secured file permissions = %v, %v", info, err)
	}
	if err := secureTorFile(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secureTorFile missing path error = %v", err)
	}
}

func TestParseTorSocksListeners(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "single listener", value: `"127.0.0.1:9050"`, want: "127.0.0.1:9050"},
		{name: "Tor listener list", value: `["127.0.0.1:9050", "[::1]:9051"]`, want: "127.0.0.1:9050"},
		{name: "IPv6 loopback", value: `"[::1]:9051"`, want: "[::1]:9051"},
		{name: "reject non-loopback", value: `"0.0.0.0:9050"`, wantErr: true},
		{name: "reject invalid port", value: `"127.0.0.1:70000"`, wantErr: true},
		{name: "reject empty value", value: "", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseTorSocksListeners(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseTorSocksListeners(%q) error = %v, want error %t", test.value, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("parseTorSocksListeners(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestTorPortHostnameAndBootstrapWaiters(t *testing.T) {
	dir := t.TempDir()
	portPath := filepath.Join(dir, "tor-state")
	if err := os.WriteFile(portPath, []byte("PORT=127.0.0.1:9050\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if address, err := waitSocksPort(context.Background(), make(chan struct{}), portPath, time.Second); err != nil || address != "127.0.0.1:9050" {
		t.Fatalf("waitSocksPort() = %q, %v", address, err)
	}
	closed := make(chan struct{})
	close(closed)
	if _, err := waitSocksPort(context.Background(), closed, filepath.Join(dir, "missing"), time.Second); err == nil {
		t.Fatal("waitSocksPort should report an exited Tor process")
	}
	hostnamePath := filepath.Join(dir, "hostname")
	hostname := strings.Repeat("a", 56) + ".onion\n"
	if err := os.WriteFile(hostnamePath, []byte(hostname), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readHostname(hostnamePath); err != nil || got != strings.TrimSpace(hostname) {
		t.Fatalf("readHostname() = %q, %v", got, err)
	}
	if got, err := waitHostname(context.Background(), make(chan struct{}), hostnamePath, time.Second); err != nil || got != strings.TrimSpace(hostname) {
		t.Fatalf("waitHostname() = %q, %v", got, err)
	}
	if _, err := waitHostname(context.Background(), closed, filepath.Join(dir, "missing"), time.Second); err == nil {
		t.Fatal("waitHostname should report an exited Tor process")
	}
	if err := bootstrapTor(context.Background(), nil, closed, time.Second); err == nil {
		t.Fatal("bootstrapTor should report an exited Tor process")
	}
	events := make(chan control.Event, 1)
	events <- &control.StatusEvent{Action: "BOOTSTRAP", Severity: "NOTICE", Arguments: map[string]string{"PROGRESS": "100"}}
	if err := bootstrapTor(context.Background(), events, make(chan struct{}), time.Second); err != nil {
		t.Fatalf("bootstrapTor successful event: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bootstrapTor(canceled, nil, make(chan struct{}), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("bootstrapTor canceled error = %v", err)
	}
}
