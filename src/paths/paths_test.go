package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- Detect tests --------------------------------------------------------

func TestDetect_NoOverrides(t *testing.T) {
	// With all empty overrides the function should succeed and return non-nil
	// paths that are non-empty strings (exact values depend on OS/uid).
	p, err := Detect("", "", "", "", "")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p == nil {
		t.Fatal("Detect returned nil")
	}
	if p.Config == "" {
		t.Error("Config path should not be empty")
	}
	if p.Data == "" {
		t.Error("Data path should not be empty")
	}
	if p.Log == "" {
		t.Error("Log path should not be empty")
	}
	if p.PID == "" {
		t.Error("PID path should not be empty")
	}
}

func TestDetect_ConfigOverride(t *testing.T) {
	p, err := Detect("/custom/config", "", "", "", "")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Config != "/custom/config" {
		t.Errorf("Config = %q, want /custom/config", p.Config)
	}
	// SSL and Security should be derived from the config override.
	if !strings.HasPrefix(p.SSL, "/custom/config") {
		t.Errorf("SSL = %q, expected prefix /custom/config", p.SSL)
	}
	if !strings.HasPrefix(p.Security, "/custom/config") {
		t.Errorf("Security = %q, expected prefix /custom/config", p.Security)
	}
}

func TestDetect_DataOverride(t *testing.T) {
	p, err := Detect("", "/custom/data", "", "", "")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Data != "/custom/data" {
		t.Errorf("Data = %q, want /custom/data", p.Data)
	}
	if !strings.HasPrefix(p.DB, "/custom/data") {
		t.Errorf("DB = %q, expected prefix /custom/data", p.DB)
	}
}

func TestDetect_CacheOverride(t *testing.T) {
	p, err := Detect("", "", "/custom/cache", "", "")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Cache != "/custom/cache" {
		t.Errorf("Cache = %q, want /custom/cache", p.Cache)
	}
}

func TestDetect_LogOverride(t *testing.T) {
	p, err := Detect("", "", "", "/custom/log", "")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Log != "/custom/log" {
		t.Errorf("Log = %q, want /custom/log", p.Log)
	}
}

func TestDetect_BackupOverride(t *testing.T) {
	p, err := Detect("", "", "", "", "/custom/backup")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Backup != "/custom/backup" {
		t.Errorf("Backup = %q, want /custom/backup", p.Backup)
	}
}

func TestDetect_AllOverrides(t *testing.T) {
	p, err := Detect("/cfg", "/dat", "/cch", "/log", "/bak")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if p.Config != "/cfg" {
		t.Errorf("Config = %q", p.Config)
	}
	if p.Data != "/dat" {
		t.Errorf("Data = %q", p.Data)
	}
	if p.Cache != "/cch" {
		t.Errorf("Cache = %q", p.Cache)
	}
	if p.Log != "/log" {
		t.Errorf("Log = %q", p.Log)
	}
	if p.Backup != "/bak" {
		t.Errorf("Backup = %q", p.Backup)
	}
}

// ---- Platform-specific path helpers -------------------------------------

func TestLinuxPrivilegedPaths(t *testing.T) {
	p := linuxPrivilegedPaths()
	if p.Config != "/etc/casapps/casspeed" {
		t.Errorf("Config = %q, want /etc/casapps/casspeed", p.Config)
	}
	if p.PID != "/var/run/casapps/casspeed.pid" {
		t.Errorf("PID = %q", p.PID)
	}
}

func TestLinuxUserPaths(t *testing.T) {
	p := linuxUserPaths()
	if p.Config == "" {
		t.Error("Config should not be empty")
	}
	if !strings.Contains(p.Config, "casapps/casspeed") {
		t.Errorf("Config = %q, expected 'casapps/casspeed'", p.Config)
	}
}

func TestContainerPaths(t *testing.T) {
	p := containerPaths()
	if p.Config != "/config" {
		t.Errorf("Config = %q, want /config", p.Config)
	}
	if p.Data != "/data" {
		t.Errorf("Data = %q, want /data", p.Data)
	}
}

func TestEnsureCreatesConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	p := &Paths{
		Config:   filepath.Join(root, "config"),
		Data:     filepath.Join(root, "data"),
		Cache:    filepath.Join(root, "cache"),
		Log:      filepath.Join(root, "log"),
		Backup:   filepath.Join(root, "backup"),
		DB:       filepath.Join(root, "data", "db"),
		PID:      filepath.Join(root, "run", "casspeed.pid"),
		SSL:      filepath.Join(root, "config", "ssl"),
		Security: filepath.Join(root, "config", "security"),
	}
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, dir := range []string{
		p.Config, p.Data, p.Cache, p.Log, p.Backup, p.DB,
		filepath.Join(p.SSL, "letsencrypt"), filepath.Join(p.SSL, "local"),
		filepath.Join(p.Security, "geoip"), filepath.Join(p.Security, "blocklists"),
		filepath.Join(p.Security, "cve"), filepath.Dir(p.PID),
	} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Errorf("Ensure did not create directory %q: info=%v err=%v", dir, info, err)
		}
	}
}

func TestEnsureReportsDirectoryCreationFailure(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(filePath, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &Paths{Config: filePath}
	if err := p.Ensure(); err == nil {
		t.Fatal("Ensure should report when a configured directory is a regular file")
	}
}
