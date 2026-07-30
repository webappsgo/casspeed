package mode

import (
	"strings"
	"testing"
)

// ---- Detect() tests ------------------------------------------------------

func TestDetect_DefaultsToProduction(t *testing.T) {
	// No flags, no env → production, no debug.
	t.Setenv("MODE", "")
	t.Setenv("DEBUG", "")

	state, err := Detect("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Mode != Production {
		t.Errorf("Mode = %q, want production", state.Mode)
	}
	if state.Debug {
		t.Error("Debug should default to false")
	}
}

func TestDetect_FlagOverridesEnv(t *testing.T) {
	// ENV says development; flag says production — flag wins.
	t.Setenv("MODE", "development")

	state, err := Detect("production", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Mode != Production {
		t.Errorf("Mode = %q, want production (flag wins over env)", state.Mode)
	}
}

func TestDetect_EnvFallback(t *testing.T) {
	// No flag; ENV = development.
	t.Setenv("MODE", "development")

	state, err := Detect("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Mode != Development {
		t.Errorf("Mode = %q, want development (from env)", state.Mode)
	}
}

func TestDetect_ModeAliases(t *testing.T) {
	cases := []struct {
		input string
		want  Mode
	}{
		{"prod", Production},
		{"production", Production},
		{"PRODUCTION", Production},
		{"dev", Development},
		{"development", Development},
		{"DEVELOPMENT", Development},
		{"  prod  ", Production},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Setenv("MODE", "")
			state, err := Detect(tc.input, "")
			if err != nil {
				t.Fatalf("Detect(%q) unexpected error: %v", tc.input, err)
			}
			if state.Mode != tc.want {
				t.Errorf("Detect(%q).Mode = %q, want %q", tc.input, state.Mode, tc.want)
			}
		})
	}
}

func TestDetect_InvalidModeReturnsError(t *testing.T) {
	t.Setenv("MODE", "")
	_, err := Detect("staging", "")
	if err == nil {
		t.Error("expected error for invalid mode 'staging'")
	}
}

func TestDetect_InvalidEnvModeReturnsError(t *testing.T) {
	t.Setenv("MODE", "banana")
	_, err := Detect("", "")
	if err == nil {
		t.Error("expected error for invalid MODE env var")
	}
}

func TestDetect_DebugFlagTrue(t *testing.T) {
	t.Setenv("DEBUG", "")
	state, err := Detect("production", "true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.Debug {
		t.Error("Debug should be true when flag is 'true'")
	}
}

func TestDetect_DebugFlagFalse(t *testing.T) {
	t.Setenv("DEBUG", "true")
	// Explicit flag=false overrides env.
	state, err := Detect("production", "false")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Debug {
		t.Error("Debug should be false when flag is 'false'")
	}
}

func TestDetect_DebugFromEnv(t *testing.T) {
	t.Setenv("DEBUG", "1")
	state, err := Detect("production", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.Debug {
		t.Error("Debug should be true from DEBUG=1 env var")
	}
}

func TestDetect_InvalidDebugFlagReturnsError(t *testing.T) {
	_, err := Detect("production", "maybe")
	if err == nil {
		t.Error("expected error for invalid debug flag 'maybe'")
	}
}

func TestDetect_InvalidDebugEnvReturnsError(t *testing.T) {
	t.Setenv("DEBUG", "certainly")
	_, err := Detect("production", "")
	if err == nil {
		t.Error("expected error for invalid DEBUG env var")
	}
}

// ---- State method tests --------------------------------------------------

func TestState_IsProduction(t *testing.T) {
	s := &State{Mode: Production}
	if !s.IsProduction() {
		t.Error("IsProduction() should be true")
	}
	if s.IsDevelopment() {
		t.Error("IsDevelopment() should be false in production")
	}
}

func TestState_IsDevelopment(t *testing.T) {
	s := &State{Mode: Development}
	if s.IsProduction() {
		t.Error("IsProduction() should be false in development")
	}
	if !s.IsDevelopment() {
		t.Error("IsDevelopment() should be true")
	}
}

func TestState_IsDebug(t *testing.T) {
	s := &State{Mode: Production, Debug: true}
	if !s.IsDebug() {
		t.Error("IsDebug() should be true when Debug=true")
	}
	s.Debug = false
	if s.IsDebug() {
		t.Error("IsDebug() should be false when Debug=false")
	}
}

func TestState_String(t *testing.T) {
	prod := &State{Mode: Production, Debug: false}
	if prod.String() != "production" {
		t.Errorf("String() = %q, want 'production'", prod.String())
	}

	prodDebug := &State{Mode: Production, Debug: true}
	if !strings.Contains(prodDebug.String(), "production") || !strings.Contains(prodDebug.String(), "debugging") {
		t.Errorf("String() with debug = %q, want to contain 'production' and 'debugging'", prodDebug.String())
	}

	dev := &State{Mode: Development, Debug: false}
	if dev.String() != "development" {
		t.Errorf("String() = %q, want 'development'", dev.String())
	}
}

func TestState_LogLevel(t *testing.T) {
	cases := []struct {
		mode  Mode
		debug bool
		want  string
	}{
		{Production, false, "info"},
		{Development, false, "debug"},
		{Production, true, "trace"},
		{Development, true, "trace"},
	}
	for _, tc := range cases {
		s := &State{Mode: tc.mode, Debug: tc.debug}
		if got := s.LogLevel(); got != tc.want {
			t.Errorf("LogLevel(mode=%s,debug=%v) = %q, want %q", tc.mode, tc.debug, got, tc.want)
		}
	}
}

func TestState_ShouldCacheTemplates(t *testing.T) {
	cases := []struct {
		mode  Mode
		debug bool
		want  bool
	}{
		{Production, false, true},
		{Production, true, false},
		{Development, false, false},
		{Development, true, false},
	}
	for _, tc := range cases {
		s := &State{Mode: tc.mode, Debug: tc.debug}
		if got := s.ShouldCacheTemplates(); got != tc.want {
			t.Errorf("ShouldCacheTemplates(mode=%s,debug=%v) = %v, want %v", tc.mode, tc.debug, got, tc.want)
		}
	}
}

func TestState_ShouldCacheStatic(t *testing.T) {
	prod := &State{Mode: Production, Debug: false}
	if !prod.ShouldCacheStatic() {
		t.Error("production+no-debug should cache static")
	}

	prodDebug := &State{Mode: Production, Debug: true}
	if prodDebug.ShouldCacheStatic() {
		t.Error("production+debug should NOT cache static")
	}
}

func TestState_ShouldEnforceRateLimit(t *testing.T) {
	prod := &State{Mode: Production}
	if !prod.ShouldEnforceRateLimit() {
		t.Error("production should enforce rate limit")
	}

	dev := &State{Mode: Development}
	if dev.ShouldEnforceRateLimit() {
		t.Error("development should not enforce rate limit")
	}
}

func TestState_ShouldShowStackTraces(t *testing.T) {
	cases := []struct {
		mode  Mode
		debug bool
		want  bool
	}{
		{Production, false, false},
		{Production, true, true},
		{Development, false, true},
		{Development, true, true},
	}
	for _, tc := range cases {
		s := &State{Mode: tc.mode, Debug: tc.debug}
		if got := s.ShouldShowStackTraces(); got != tc.want {
			t.Errorf("ShouldShowStackTraces(mode=%s,debug=%v) = %v, want %v", tc.mode, tc.debug, got, tc.want)
		}
	}
}

func TestState_ShouldEnableDebugEndpoints(t *testing.T) {
	noDebug := &State{Mode: Production, Debug: false}
	if noDebug.ShouldEnableDebugEndpoints() {
		t.Error("debug endpoints should not be enabled without debug flag")
	}

	withDebug := &State{Mode: Production, Debug: true}
	if !withDebug.ShouldEnableDebugEndpoints() {
		t.Error("debug endpoints should be enabled with debug flag")
	}
}

func TestState_ShouldEnablePprof(t *testing.T) {
	s := &State{Mode: Development, Debug: false}
	if s.ShouldEnablePprof() {
		t.Error("pprof should not be enabled without debug flag")
	}

	s.Debug = true
	if !s.ShouldEnablePprof() {
		t.Error("pprof should be enabled with debug flag")
	}
}

func TestState_ShouldVerboseLog(t *testing.T) {
	prod := &State{Mode: Production, Debug: false}
	if prod.ShouldVerboseLog() {
		t.Error("production without debug should not verbose log")
	}

	dev := &State{Mode: Development, Debug: false}
	if !dev.ShouldVerboseLog() {
		t.Error("development should verbose log")
	}

	prodDebug := &State{Mode: Production, Debug: true}
	if !prodDebug.ShouldVerboseLog() {
		t.Error("production with debug should verbose log")
	}
}

func TestState_GetConsoleIcon(t *testing.T) {
	cases := []struct {
		mode  Mode
		debug bool
	}{
		{Production, false},
		{Production, true},
		{Development, false},
		{Development, true},
	}
	for _, tc := range cases {
		s := &State{Mode: tc.mode, Debug: tc.debug}
		icon := s.GetConsoleIcon()
		// Just ensure non-empty; the exact emoji can change without breaking behavior.
		if icon == "" {
			t.Errorf("GetConsoleIcon(mode=%s,debug=%v) returned empty string", tc.mode, tc.debug)
		}
	}
}
