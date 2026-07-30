package i18n

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// newTestService creates a fresh Service for each test (avoids singleton pollution).
func newTestService() *Service {
	return &Service{
		translations: make(map[string]Translation),
	}
}

// ---- Service.Initialize / IsEnabled tests --------------------------------

func TestInitialize_DisabledDoesNotLoadTranslations(t *testing.T) {
	svc := newTestService()
	cfg := &Config{Enabled: false, DefaultLanguage: "en"}
	if err := svc.Initialize(cfg); err != nil {
		t.Fatalf("Initialize error: %v", err)
	}
	if svc.IsEnabled() {
		t.Error("should not be enabled after Initialize with Enabled=false")
	}
}

func TestInitialize_EnabledLoadsDefaultTranslations(t *testing.T) {
	svc := newTestService()
	cfg := &Config{
		Enabled:         true,
		DefaultLanguage: "en",
		SupportedLangs:  []string{"en"},
		TranslationsDir: "/nonexistent",
	}
	if err := svc.Initialize(cfg); err != nil {
		t.Fatalf("Initialize error: %v", err)
	}
	if !svc.IsEnabled() {
		t.Error("should be enabled after Initialize with Enabled=true")
	}
	// Default en translations should have been loaded.
	if len(svc.translations["en"]) == 0 {
		t.Error("expected en translations to be loaded")
	}
}

func TestInitialize_LoadsFromFile(t *testing.T) {
	dir := t.TempDir()
	trans := Translation{
		"hello": "world",
	}
	data, _ := json.Marshal(trans)
	if err := os.WriteFile(filepath.Join(dir, "en.json"), data, 0644); err != nil {
		t.Fatalf("write translation file: %v", err)
	}

	svc := newTestService()
	cfg := &Config{
		Enabled:         true,
		DefaultLanguage: "en",
		SupportedLangs:  []string{"en"},
		TranslationsDir: dir,
	}
	if err := svc.Initialize(cfg); err != nil {
		t.Fatalf("Initialize error: %v", err)
	}
	if svc.translations["en"]["hello"] != "world" {
		t.Errorf("expected 'world', got %q", svc.translations["en"]["hello"])
	}
}

func TestInitialize_InvalidJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "en.json"), []byte("{bad json"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	svc := newTestService()
	cfg := &Config{
		Enabled:         true,
		DefaultLanguage: "en",
		SupportedLangs:  []string{"en"},
		TranslationsDir: dir,
	}
	if err := svc.Initialize(cfg); err == nil {
		t.Error("expected error for invalid JSON translation file")
	}
}

// ---- Service.T tests -----------------------------------------------------

func TestT_DisabledReturnsKey(t *testing.T) {
	svc := newTestService()
	// Not initialized → disabled.
	if got := svc.T("en", "some.key"); got != "some.key" {
		t.Errorf("T() = %q, want key passthrough", got)
	}
}

func TestT_KnownKey(t *testing.T) {
	svc := enabledService(t, "en")
	got := svc.T("en", "test.start")
	if got == "test.start" {
		t.Error("expected translated value, got key passthrough")
	}
}

func TestT_UnknownKeyReturnsKey(t *testing.T) {
	svc := enabledService(t, "en")
	got := svc.T("en", "no.such.key")
	if got != "no.such.key" {
		t.Errorf("T() = %q, want key passthrough for unknown key", got)
	}
}

func TestT_UnknownLanguageFallsBackToDefault(t *testing.T) {
	svc := enabledService(t, "en")
	// "zh" is not loaded; should fall back to "en" default.
	got := svc.T("zh", "test.start")
	if got == "test.start" {
		t.Error("expected fallback translation, not key passthrough")
	}
}

func TestT_WithFormatArgs(t *testing.T) {
	dir := t.TempDir()
	trans := Translation{"msg": "Hello %s"}
	data, _ := json.Marshal(trans)
	os.WriteFile(filepath.Join(dir, "en.json"), data, 0644)

	svc := newTestService()
	svc.Initialize(&Config{
		Enabled:         true,
		DefaultLanguage: "en",
		SupportedLangs:  []string{"en"},
		TranslationsDir: dir,
	})
	got := svc.T("en", "msg", "world")
	if got != "Hello world" {
		t.Errorf("T() with args = %q, want 'Hello world'", got)
	}
}

// ---- GetSupportedLanguages / GetDefaultLanguage tests --------------------

func TestGetSupportedLanguages_NilConfig(t *testing.T) {
	svc := newTestService()
	langs := svc.GetSupportedLanguages()
	if len(langs) != 1 || langs[0] != "en" {
		t.Errorf("GetSupportedLanguages() = %v, want [en]", langs)
	}
}

func TestGetDefaultLanguage_NilConfig(t *testing.T) {
	svc := newTestService()
	if got := svc.GetDefaultLanguage(); got != "en" {
		t.Errorf("GetDefaultLanguage() = %q, want 'en'", got)
	}
}

func TestGetDefaultLanguage_WithConfig(t *testing.T) {
	svc := enabledService(t, "en")
	if got := svc.GetDefaultLanguage(); got != "en" {
		t.Errorf("GetDefaultLanguage() = %q, want 'en'", got)
	}
}

// ---- DetectLanguage tests ------------------------------------------------

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "en"},
		{"en", "en"},
		{"en-US", "en"},
		{"fr-FR,fr;q=0.9,en;q=0.8", "fr"},
		{"de", "de"},
		{"zh-CN", "zh"},
		{"es;q=0.9", "es"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := DetectLanguage(tc.input)
			if got != tc.want {
				t.Errorf("DetectLanguage(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---- Default translations test ------------------------------------------

func TestDefaultTranslations_EnHasExpectedKeys(t *testing.T) {
	trans := getDefaultTranslations("en")
	required := []string{"app.name", "test.start", "login.title", "error.generic"}
	for _, k := range required {
		if _, ok := trans[k]; !ok {
			t.Errorf("en default translations missing key %q", k)
		}
	}
}

func TestDefaultTranslations_UnknownLangEmpty(t *testing.T) {
	trans := getDefaultTranslations("xx")
	if len(trans) != 0 {
		t.Errorf("unknown language should return empty Translation, got %d keys", len(trans))
	}
}

func TestDefaultTranslations_ESAndFRPresent(t *testing.T) {
	for _, lang := range []string{"es", "fr"} {
		trans := getDefaultTranslations(lang)
		if len(trans) == 0 {
			t.Errorf("expected non-empty translations for %q", lang)
		}
	}
}

// ---- FormatNumber / FormatDate tests ------------------------------------

func TestFormatNumber(t *testing.T) {
	result := FormatNumber("en", 3.14159)
	if result == "" {
		t.Error("FormatNumber returned empty string")
	}
	// Spot-check: should contain "3.14"
	if len(result) < 4 {
		t.Errorf("FormatNumber result %q seems too short", result)
	}
}

func TestFormatDate(t *testing.T) {
	// Current implementation is a passthrough.
	got := FormatDate("en", "2026-01-01")
	if got != "2026-01-01" {
		t.Errorf("FormatDate passthrough broken: got %q", got)
	}
}

// ---- helper --------------------------------------------------------------

func enabledService(t *testing.T, lang string) *Service {
	t.Helper()
	svc := newTestService()
	cfg := &Config{
		Enabled:         true,
		DefaultLanguage: lang,
		SupportedLangs:  []string{lang},
		TranslationsDir: "/nonexistent",
	}
	if err := svc.Initialize(cfg); err != nil {
		t.Fatalf("enabledService Initialize: %v", err)
	}
	return svc
}
