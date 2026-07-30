package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- Default() tests -----------------------------------------------------

func TestDefault_NotNil(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
}

func TestDefault_BrandingTitle(t *testing.T) {
	cfg := Default()
	if cfg.Server.Branding.Title != "casspeed" {
		t.Errorf("Branding.Title = %q, want %q", cfg.Server.Branding.Title, "casspeed")
	}
}

func TestDefault_AdminPath(t *testing.T) {
	cfg := Default()
	if cfg.Server.AdminPath != "admin" {
		t.Errorf("AdminPath = %q, want %q", cfg.Server.AdminPath, "admin")
	}
}

func TestDefault_Mode(t *testing.T) {
	cfg := Default()
	if cfg.Server.Mode != "production" {
		t.Errorf("Mode = %q, want %q", cfg.Server.Mode, "production")
	}
}

func TestDefault_SSLDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Server.SSL.Enabled {
		t.Error("SSL.Enabled should default to false")
	}
	if cfg.Server.SSL.MinVersion != "TLS1.2" {
		t.Errorf("SSL.MinVersion = %q, want TLS1.2", cfg.Server.SSL.MinVersion)
	}
}

func TestDefault_TestConfig(t *testing.T) {
	cfg := Default()
	if cfg.Test.MaxConcurrent < 1 {
		t.Errorf("Test.MaxConcurrent = %d, want >= 1", cfg.Test.MaxConcurrent)
	}
	if cfg.Test.MaxThreads < 1 || cfg.Test.MaxThreads > 16 {
		t.Errorf("Test.MaxThreads = %d, want in [1,16]", cfg.Test.MaxThreads)
	}
	if cfg.Test.ChunkSize < 65536 || cfg.Test.ChunkSize > 10485760 {
		t.Errorf("Test.ChunkSize = %d, out of valid range", cfg.Test.ChunkSize)
	}
	if cfg.Test.Timeout < 10 {
		t.Errorf("Test.Timeout = %d, want >= 10", cfg.Test.Timeout)
	}
}

func TestDefault_SchedulerTasks(t *testing.T) {
	cfg := Default()
	expectedTasks := []string{"log_rotation", "session_cleanup", "backup", "ssl_renewal", "health_check"}
	for _, name := range expectedTasks {
		if _, ok := cfg.Server.Scheduler.Tasks[name]; !ok {
			t.Errorf("missing expected scheduler task %q", name)
		}
	}
}

func TestDefault_RateLimit(t *testing.T) {
	cfg := Default()
	if !cfg.Server.RateLimit.Enabled {
		t.Error("RateLimit.Enabled should default to true")
	}
	if cfg.Server.RateLimit.Requests <= 0 {
		t.Errorf("RateLimit.Requests = %d, want > 0", cfg.Server.RateLimit.Requests)
	}
}

func TestDefault_ThemeIsDark(t *testing.T) {
	cfg := Default()
	if cfg.Web.UI.Theme != "dark" {
		t.Errorf("Web.UI.Theme = %q, want dark", cfg.Web.UI.Theme)
	}
}

// ---- Validate() tests ----------------------------------------------------

func validConfig() *Config {
	cfg := Default()
	// Ensure all required fields satisfy the validator.
	cfg.Server.Mode = "production"
	cfg.Server.SSL.MinVersion = "TLS1.2"
	cfg.Server.SSL.LetsEncrypt.Challenge = "http-01"
	cfg.Test.MaxConcurrent = 3
	cfg.Test.MinInterval = 5
	cfg.Test.DefaultDuration = 10
	cfg.Test.MaxThreads = 4
	cfg.Test.ChunkSize = 1048576
	cfg.Test.Timeout = 30
	return cfg
}

func TestValidate_ValidConfigNoError(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Mode = "staging"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidate_ValidModes(t *testing.T) {
	for _, mode := range []string{"production", "development"} {
		cfg := validConfig()
		cfg.Server.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Errorf("mode %q should be valid, got: %v", mode, err)
		}
	}
}

func TestValidate_InvalidSSLMinVersion(t *testing.T) {
	cfg := validConfig()
	cfg.Server.SSL.MinVersion = "TLS1.0"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for TLS1.0 min version")
	}
}

func TestValidate_ValidSSLMinVersions(t *testing.T) {
	for _, v := range []string{"TLS1.2", "TLS1.3"} {
		cfg := validConfig()
		cfg.Server.SSL.MinVersion = v
		if err := cfg.Validate(); err != nil {
			t.Errorf("SSL min version %q should be valid, got: %v", v, err)
		}
	}
}

func TestValidate_InvalidLetsEncryptChallenge(t *testing.T) {
	cfg := validConfig()
	cfg.Server.SSL.LetsEncrypt.Challenge = "ftp-01"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid LE challenge")
	}
}

func TestValidate_ValidLetsEncryptChallenges(t *testing.T) {
	for _, ch := range []string{"http-01", "tls-alpn-01", "dns-01"} {
		cfg := validConfig()
		cfg.Server.SSL.LetsEncrypt.Challenge = ch
		if err := cfg.Validate(); err != nil {
			t.Errorf("challenge %q should be valid, got: %v", ch, err)
		}
	}
}

func TestValidate_TestMaxConcurrentZero(t *testing.T) {
	cfg := validConfig()
	cfg.Test.MaxConcurrent = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for MaxConcurrent=0")
	}
}

func TestValidate_TestMinIntervalNegative(t *testing.T) {
	cfg := validConfig()
	cfg.Test.MinInterval = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for MinInterval=-1")
	}
}

func TestValidate_TestDefaultDurationZero(t *testing.T) {
	cfg := validConfig()
	cfg.Test.DefaultDuration = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for DefaultDuration=0")
	}
}

func TestValidate_TestMaxThreadsBounds(t *testing.T) {
	cases := []struct {
		threads int
		valid   bool
	}{
		{0, false},
		{1, true},
		{8, true},
		{16, true},
		{17, false},
	}
	for _, tc := range cases {
		cfg := validConfig()
		cfg.Test.MaxThreads = tc.threads
		err := cfg.Validate()
		if tc.valid && err != nil {
			t.Errorf("MaxThreads=%d should be valid, got: %v", tc.threads, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("MaxThreads=%d should be invalid", tc.threads)
		}
	}
}

func TestValidate_TestChunkSizeBounds(t *testing.T) {
	cases := []struct {
		size  int
		valid bool
	}{
		{65535, false},
		{65536, true},
		{1048576, true},
		{10485760, true},
		{10485761, false},
	}
	for _, tc := range cases {
		cfg := validConfig()
		cfg.Test.ChunkSize = tc.size
		err := cfg.Validate()
		if tc.valid && err != nil {
			t.Errorf("ChunkSize=%d should be valid, got: %v", tc.size, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("ChunkSize=%d should be invalid", tc.size)
		}
	}
}

func TestValidate_TestTimeoutTooLow(t *testing.T) {
	cfg := validConfig()
	cfg.Test.Timeout = 9
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for Timeout=9")
	}
}

func TestValidate_TestTimeoutMinimum(t *testing.T) {
	cfg := validConfig()
	cfg.Test.Timeout = 10
	if err := cfg.Validate(); err != nil {
		t.Errorf("Timeout=10 should be valid, got: %v", err)
	}
}

// ---- ParseDuration tests -------------------------------------------------

func TestParseDuration(t *testing.T) {
	cases := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"30d", 30 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"2h", 2 * time.Hour, false},
		{"15m", 15 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"", 0, true},
		{"x", 0, true},
		{"5w", 0, true},
		{"bad", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseDuration(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseDuration(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---- Load() tests --------------------------------------------------------

func TestLoad_NonExistentFileReturnsDefaults(t *testing.T) {
	cfg, err := Load("/tmp/casspeed_test_nonexistent_12345.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Server.Branding.Title != "casspeed" {
		t.Errorf("expected default branding, got: %q", cfg.Server.Branding.Title)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `server:
  mode: development
  admin_path: myadmin
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Server.Mode != "development" {
		t.Errorf("Mode = %q, want development", cfg.Server.Mode)
	}
	if cfg.Server.AdminPath != "myadmin" {
		t.Errorf("AdminPath = %q, want myadmin", cfg.Server.AdminPath)
	}
}

func TestLoad_InvalidYAMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(cfgPath, []byte("{{{{not yaml"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// ---- Save() tests --------------------------------------------------------

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sub", "config.yaml")

	original := Default()
	original.Server.Mode = "development"
	original.Server.AdminPath = "testadmin"

	if err := Save(original, cfgPath); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if loaded.Server.Mode != "development" {
		t.Errorf("Mode after round-trip = %q, want development", loaded.Server.Mode)
	}
	if loaded.Server.AdminPath != "testadmin" {
		t.Errorf("AdminPath after round-trip = %q, want testadmin", loaded.Server.AdminPath)
	}
}

// ---- ParseBool tests -----------------------------------------------------

func TestParseBool_TruthyValues(t *testing.T) {
	truthy := []string{"1", "y", "t", "yes", "true", "on", "ok", "enable", "enabled",
		"yep", "yup", "yeah", "aye", "si", "oui", "da", "hai",
		"affirmative", "accept", "allow", "grant", "sure", "totally",
		"YES", "TRUE", "On", " true "}
	for _, s := range truthy {
		got, err := ParseBool(s, false)
		if err != nil {
			t.Errorf("ParseBool(%q) unexpected error: %v", s, err)
		}
		if !got {
			t.Errorf("ParseBool(%q) = false, want true", s)
		}
	}
}

func TestParseBool_FalsyValues(t *testing.T) {
	falsy := []string{"0", "n", "f", "no", "false", "off", "disable", "disabled",
		"nope", "nah", "nay", "nein", "non", "niet", "iie", "lie",
		"negative", "reject", "block", "revoke", "deny", "never", "noway",
		"FALSE", "NO", "Off", " false "}
	for _, s := range falsy {
		got, err := ParseBool(s, true)
		if err != nil {
			t.Errorf("ParseBool(%q) unexpected error: %v", s, err)
		}
		if got {
			t.Errorf("ParseBool(%q) = true, want false", s)
		}
	}
}

func TestParseBool_EmptyUsesDefault(t *testing.T) {
	got, err := ParseBool("", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("empty string should return default=true")
	}

	got, err = ParseBool("", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("empty string should return default=false")
	}
}

func TestParseBool_InvalidReturnsError(t *testing.T) {
	invalids := []string{"maybe", "2", "yesno", "tru", "fals", "random"}
	for _, s := range invalids {
		_, err := ParseBool(s, false)
		if err == nil {
			t.Errorf("ParseBool(%q) expected error, got nil", s)
		}
	}
}

func TestMustParseBool_ValidDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustParseBool panicked unexpectedly: %v", r)
		}
	}()
	v := MustParseBool("true", false)
	if !v {
		t.Error("expected true")
	}
}

func TestMustParseBool_InvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseBool should panic on invalid input")
		}
	}()
	MustParseBool("maybe", false)
}

func TestIsTruthy(t *testing.T) {
	if !IsTruthy("yes") {
		t.Error("IsTruthy(yes) should be true")
	}
	if IsTruthy("no") {
		t.Error("IsTruthy(no) should be false")
	}
	if IsTruthy("") {
		t.Error("IsTruthy('') should be false")
	}
	if IsTruthy("maybe") {
		t.Error("IsTruthy(maybe) should be false")
	}
}

func TestIsFalsy(t *testing.T) {
	if !IsFalsy("no") {
		t.Error("IsFalsy(no) should be true")
	}
	if IsFalsy("yes") {
		t.Error("IsFalsy(yes) should be false")
	}
	if IsFalsy("") {
		t.Error("IsFalsy('') should be false")
	}
}

// ---- Database default test -----------------------------------------------

func TestDefault_DatabaseDriverIsFile(t *testing.T) {
	cfg := Default()
	if cfg.Server.Database.Driver != "file" {
		t.Errorf("Database.Driver = %q, want file", cfg.Server.Database.Driver)
	}
}

// ---- Idempotency ---------------------------------------------------------

func TestDefault_CalledTwiceProducesEquivalentConfigs(t *testing.T) {
	c1 := Default()
	c2 := Default()
	if c1.Server.Branding.Title != c2.Server.Branding.Title {
		t.Error("Default() is not idempotent")
	}
	if c1.Server.AdminPath != c2.Server.AdminPath {
		t.Error("Default() AdminPath differs between calls")
	}
	// Test config should be identical between calls
	if c1.Test.DefaultDuration != c2.Test.DefaultDuration {
		t.Error("Default() Test.DefaultDuration differs between calls")
	}
}

// ---- AdminConfig default email contains hostname -------------------------

func TestDefault_AdminEmailContainsAt(t *testing.T) {
	cfg := Default()
	if !strings.Contains(cfg.Server.Admin.Email, "@") {
		t.Errorf("Admin.Email %q missing '@'", cfg.Server.Admin.Email)
	}
}
