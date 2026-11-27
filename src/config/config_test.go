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

func TestLoadSeedsCacheURLAndKeepsCredentialsOutOfServerConfig(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "server.yml")
	t.Setenv("CACHE_URL", "valkey://user:private@cache.example:6379/0")
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Cache.Type != "valkey" || cfg.Server.Cache.URL == "" {
		t.Fatalf("cache config was not seeded: %#v", cfg.Server.Cache)
	}
	if err := Save(cfg, configPath); err != nil {
		t.Fatal(err)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configBytes), "private") {
		t.Fatal("cache credential leaked into server.yml")
	}
	secretBytes, err := os.ReadFile(filepath.Join(configDir, "secrets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secretBytes), "private") {
		t.Fatal("cache credential missing from secrets.yml")
	}
	info, err := os.Stat(filepath.Join(configDir, "secrets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secrets.yml mode = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadCacheURLFromSecretsOverridesEnvironment(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "server.yml")
	if err := os.WriteFile(configPath, []byte("server:\n  cache:\n    type: valkey\n    url: ''\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "secrets.yml"), []byte("server:\n  cache:\n    url: valkey://user:saved@cache.example:6379/0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CACHE_URL", "valkey://user:ignored@other.example:6379/0")
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Server.Cache.URL, "saved@") || strings.Contains(cfg.Server.Cache.URL, "ignored") {
		t.Fatalf("saved cache URL precedence failed: %q", cfg.Server.Cache.URL)
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
	if cfg.Server.AdminPath != "administration" {
		t.Errorf("AdminPath = %q, want %q", cfg.Server.AdminPath, "administration")
	}
}

func TestDefault_Mode(t *testing.T) {
	cfg := Default()
	if cfg.Server.Mode != "production" {
		t.Errorf("Mode = %q, want %q", cfg.Server.Mode, "production")
	}
}

func TestDefault_UsersRegistrationIsOpen(t *testing.T) {
	cfg := Default()
	if !cfg.Server.Users.Enabled || cfg.Server.Users.Registration.Mode != "open" || !cfg.Server.Users.Registration.RequireEmailVerification || cfg.Server.Users.Roles.Default != "user" || len(cfg.Server.Users.Roles.Available) != 2 || cfg.Server.Users.Auth.PasswordMinLength != 8 || !cfg.Server.Users.Auth.Allow2FA {
		t.Fatalf("users config = %#v, want enabled open registration, roles, password policy and email verification", cfg.Server.Users)
	}
}

func TestValidateRejectsUserRoleDefaultNotInAvailable(t *testing.T) {
	cfg := Default()
	cfg.Server.Users.Roles.Default = "moderator"
	if err := cfg.Validate(); err == nil {
		t.Fatal("configuration accepted an undefined default user role")
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
	if cfg.Server.RateLimit.Read.Requests != 120 || cfg.Server.RateLimit.Read.Window != 60 {
		t.Errorf("Read rate limit = %#v, want 120 requests / 60s", cfg.Server.RateLimit.Read)
	}
	if cfg.Server.RateLimit.Write.Requests != 10 || cfg.Server.RateLimit.GlobalBurst != 240 {
		t.Errorf("write/global rate limits = %#v/%d, want 10/240", cfg.Server.RateLimit.Write, cfg.Server.RateLimit.GlobalBurst)
	}
}

func TestDefault_I18nUsesEmbeddedLocaleRegistry(t *testing.T) {
	cfg := Default()
	if cfg.Server.I18n.DefaultLanguage != "en" || len(cfg.Server.I18n.AvailableLanguages) < 6 {
		t.Fatalf("default i18n config = %#v", cfg.Server.I18n)
	}
	for _, language := range []string{"en", "es", "fr", "de", "it", "ar"} {
		found := false
		for _, available := range cfg.Server.I18n.AvailableLanguages {
			if available == language {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required locale %q missing from defaults", language)
		}
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

func TestValidateTrackingProviders(t *testing.T) {
	valid := []TrackingConfig{
		{Type: "none"}, {Type: "google", ID: "G-ABC123"},
		{Type: "matomo", ID: "1", URL: "https://metrics.example"},
		{Type: "piwik", ID: "2", URL: "http://metrics.example"},
		{Type: "owa", ID: "site", URL: "https://metrics.example"},
		{Type: "fathom", ID: "site"}, {Type: "plausible", ID: "example.org"},
		{Type: "umami", ID: "12345678-1234-1234-1234-123456789abc", URL: "https://metrics.example"},
		{Type: "simple"}, {Type: "cloudflare", ID: "beacon"},
	}
	for _, tracking := range valid {
		if err := ValidateTracking(&tracking); err != nil {
			t.Errorf("valid tracking config %+v: %v", tracking, err)
		}
	}
	invalid := []TrackingConfig{
		{Type: "other"}, {Type: "google", ID: "G-invalid"}, {Type: "matomo", ID: "abc", URL: "https://metrics.example"},
		{Type: "owa", ID: "site"}, {Type: "umami", ID: "not-a-uuid", URL: "https://metrics.example"},
		{Type: "cloudflare"}, {Type: "fathom", ID: "site", URL: "javascript:alert(1)"},
	}
	for _, tracking := range invalid {
		if err := ValidateTracking(&tracking); err == nil {
			t.Errorf("invalid tracking config accepted: %+v", tracking)
		}
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
	if info, err := os.Stat(cfgPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("saved config mode = %v, err=%v, want 600", info, err)
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

func TestLoadSecuresExistingConfigPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("server:\n  mode: production\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil || fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("config file mode = %v, err=%v, want 600", fileInfo, err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("config directory mode = %v, err=%v, want 700", dirInfo, err)
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

func TestLoadOrCreateSecretsPersistsPrivateEncryptionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yml")
	first, err := LoadOrCreateSecrets(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSecrets: %v", err)
	}
	if len(first.EncryptionKey) != 32 || first.EncryptionKeyVersion != 1 || !validOperatorToken(first.ServerToken) || !first.ServerTokenGenerated || !first.EncryptionKeyGenerated {
		t.Fatalf("unexpected generated secrets: key length %d, version %d, valid operator token %t, token generated %t, encryption key generated %t", len(first.EncryptionKey), first.EncryptionKeyVersion, validOperatorToken(first.ServerToken), first.ServerTokenGenerated, first.EncryptionKeyGenerated)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secrets file mode = %o, want 600", info.Mode().Perm())
	}
	second, err := LoadOrCreateSecrets(path)
	if err != nil {
		t.Fatalf("reload secrets: %v", err)
	}
	if string(first.EncryptionKey) != string(second.EncryptionKey) || first.EncryptionKeyVersion != second.EncryptionKeyVersion {
		t.Fatal("reloading secrets changed persisted key material")
	}
	if first.ServerToken != second.ServerToken || second.ServerTokenGenerated || second.EncryptionKeyGenerated {
		t.Fatal("reloading secrets changed the operator token or reported it as newly generated")
	}
}
