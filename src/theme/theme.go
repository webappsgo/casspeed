package theme

import (
	"net/http"
)

// Theme values
const (
	ThemeLight = "light"
	ThemeDark  = "dark"
	ThemeAuto  = "auto"
)

// DefaultTheme is the default theme (dark per spec)
const DefaultTheme = ThemeDark

// DetectTheme detects the theme preference from request
// Priority: query param > cookie > header > default (dark)
func DetectTheme(r *http.Request) string {
	// 1. Query parameter ?theme=light|dark|auto
	if theme := r.URL.Query().Get("theme"); isValidTheme(theme) {
		return theme
	}

	// 2. Cookie
	if cookie, err := r.Cookie("theme"); err == nil && isValidTheme(cookie.Value) {
		return cookie.Value
	}

	// 3. Header (for API clients)
	if theme := r.Header.Get("X-Theme"); isValidTheme(theme) {
		return theme
	}

	// 4. Default (dark per spec)
	return DefaultTheme
}

// isValidTheme checks if theme value is valid
func isValidTheme(theme string) bool {
	return theme == ThemeLight || theme == ThemeDark || theme == ThemeAuto
}

// SetThemeCookie sets the theme cookie
func SetThemeCookie(w http.ResponseWriter, theme string) {
	if !isValidTheme(theme) {
		theme = DefaultTheme
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    theme,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: false,               // JavaScript needs to read this
		Secure:   false,               // Set to true if HTTPS only
		SameSite: http.SameSiteLaxMode,
	})
}

// GetThemeCSS returns CSS for the theme
// Used for inline <style> blocks when external CSS not practical
func GetThemeCSS(theme string) string {
	switch theme {
	case ThemeLight:
		return `
		:root {
			--bg-color: #ffffff;
			--text-color: #333333;
			--border-color: #dddddd;
			--link-color: #0066cc;
			--hover-color: #f5f5f5;
		}
		body {
			background-color: var(--bg-color);
			color: var(--text-color);
		}
		`
	case ThemeDark:
		return `
		:root {
			--bg-color: #1a1a1a;
			--text-color: #e0e0e0;
			--border-color: #333333;
			--link-color: #66b3ff;
			--hover-color: #2a2a2a;
		}
		body {
			background-color: var(--bg-color);
			color: var(--text-color);
		}
		`
	case ThemeAuto:
		return `
		@media (prefers-color-scheme: light) {
			:root {
				--bg-color: #ffffff;
				--text-color: #333333;
				--border-color: #dddddd;
				--link-color: #0066cc;
				--hover-color: #f5f5f5;
			}
		}
		@media (prefers-color-scheme: dark) {
			:root {
				--bg-color: #1a1a1a;
				--text-color: #e0e0e0;
				--border-color: #333333;
				--link-color: #66b3ff;
				--hover-color: #2a2a2a;
			}
		}
		body {
			background-color: var(--bg-color);
			color: var(--text-color);
		}
		`
	default:
		return GetThemeCSS(DefaultTheme)
	}
}
