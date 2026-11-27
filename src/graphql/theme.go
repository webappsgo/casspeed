package graphql

import (
	"net/http"

	"github.com/casapps/casspeed/src/theme"
)

// DetectTheme uses the shared application theme preference resolver.
func DetectTheme(r *http.Request) string {
	return theme.DetectTheme(r)
}

// GetThemeClass returns a safe class consumed by the shared project stylesheets.
func GetThemeClass(preference string) string {
	switch preference {
	case "light":
		return "theme-light"
	case "auto":
		return "theme-auto"
	default:
		return "theme-dark"
	}
}
