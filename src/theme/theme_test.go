package theme

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- isValidTheme tests --------------------------------------------------

func TestIsValidTheme(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{ThemeLight, true},
		{ThemeDark, true},
		{ThemeAuto, true},
		{"", false},
		{"unknown", false},
		{"DARK", false},
		{"Light", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := isValidTheme(tc.input); got != tc.want {
				t.Errorf("isValidTheme(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---- DetectTheme tests ---------------------------------------------------

func TestDetectTheme_Default(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := DetectTheme(req)
	if got != DefaultTheme {
		t.Errorf("DetectTheme (no params) = %q, want %q", got, DefaultTheme)
	}
}

func TestDetectTheme_QueryParam(t *testing.T) {
	for _, theme := range []string{ThemeLight, ThemeDark, ThemeAuto} {
		req := httptest.NewRequest(http.MethodGet, "/?theme="+theme, nil)
		got := DetectTheme(req)
		if got != theme {
			t.Errorf("DetectTheme (query=%s) = %q, want %q", theme, got, theme)
		}
	}
}

func TestDetectTheme_InvalidQueryParamFallsThrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?theme=rainbow", nil)
	got := DetectTheme(req)
	if got != DefaultTheme {
		t.Errorf("DetectTheme (bad query) = %q, want default %q", got, DefaultTheme)
	}
}

func TestDetectTheme_Cookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: ThemeLight})
	got := DetectTheme(req)
	if got != ThemeLight {
		t.Errorf("DetectTheme (cookie) = %q, want %q", got, ThemeLight)
	}
}

func TestDetectTheme_InvalidCookieFallsToHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "invalid"})
	req.Header.Set("X-Theme", ThemeAuto)
	got := DetectTheme(req)
	if got != ThemeAuto {
		t.Errorf("DetectTheme (bad cookie, header=%s) = %q", ThemeAuto, got)
	}
}

func TestDetectTheme_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Theme", ThemeDark)
	got := DetectTheme(req)
	if got != ThemeDark {
		t.Errorf("DetectTheme (header) = %q, want %q", got, ThemeDark)
	}
}

func TestDetectTheme_InvalidHeaderFallsToDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Theme", "midnight")
	got := DetectTheme(req)
	if got != DefaultTheme {
		t.Errorf("DetectTheme (bad header) = %q, want default", got)
	}
}

func TestDetectTheme_QueryOverridesCookie(t *testing.T) {
	// Query param has highest priority.
	req := httptest.NewRequest(http.MethodGet, "/?theme="+ThemeDark, nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: ThemeLight})
	got := DetectTheme(req)
	if got != ThemeDark {
		t.Errorf("query should win over cookie: got %q", got)
	}
}

// ---- SetThemeCookie tests ------------------------------------------------

func TestSetThemeCookie_SetsValidCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	SetThemeCookie(rr, ThemeLight)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a cookie to be set")
	}
	c := cookies[0]
	if c.Name != "theme" {
		t.Errorf("cookie name = %q, want 'theme'", c.Name)
	}
	if c.Value != ThemeLight {
		t.Errorf("cookie value = %q, want %q", c.Value, ThemeLight)
	}
}

func TestSetThemeCookie_InvalidThemeUsesDefault(t *testing.T) {
	rr := httptest.NewRecorder()
	SetThemeCookie(rr, "rainbow")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a cookie to be set")
	}
	if cookies[0].Value != DefaultTheme {
		t.Errorf("cookie value = %q, want default %q", cookies[0].Value, DefaultTheme)
	}
}

// ---- GetThemeCSS tests ---------------------------------------------------

func TestGetThemeCSS_Light(t *testing.T) {
	css := GetThemeCSS(ThemeLight)
	if !strings.Contains(css, "--bg-color") {
		t.Errorf("light CSS missing --bg-color")
	}
	if !strings.Contains(css, "#ffffff") {
		t.Errorf("light CSS should contain #ffffff background")
	}
}

func TestGetThemeCSS_Dark(t *testing.T) {
	css := GetThemeCSS(ThemeDark)
	if !strings.Contains(css, "--bg-color") {
		t.Errorf("dark CSS missing --bg-color")
	}
	if !strings.Contains(css, "#1a1a1a") {
		t.Errorf("dark CSS should contain #1a1a1a background")
	}
}

func TestGetThemeCSS_Auto(t *testing.T) {
	css := GetThemeCSS(ThemeAuto)
	if !strings.Contains(css, "prefers-color-scheme") {
		t.Errorf("auto CSS should contain media query for prefers-color-scheme")
	}
}

func TestGetThemeCSS_Unknown_FallsBackToDark(t *testing.T) {
	css := GetThemeCSS("unknown")
	// Falls back to default (dark).
	darkCSS := GetThemeCSS(ThemeDark)
	if css != darkCSS {
		t.Errorf("unknown theme CSS should equal default dark CSS")
	}
}

func TestGetThemeCSS_Empty_FallsBackToDark(t *testing.T) {
	css := GetThemeCSS("")
	darkCSS := GetThemeCSS(ThemeDark)
	if css != darkCSS {
		t.Errorf("empty theme CSS should equal default dark CSS")
	}
}

func TestGetThemeCSS_AllContainBody(t *testing.T) {
	for _, theme := range []string{ThemeLight, ThemeDark, ThemeAuto} {
		if !strings.Contains(GetThemeCSS(theme), "body") {
			t.Errorf("theme %q CSS missing 'body' rule", theme)
		}
	}
}
