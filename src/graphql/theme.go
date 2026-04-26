package graphql

import (
	"net/http"

	"github.com/casapps/casspeed/src/theme"
)

// DetectTheme uses central theme system
func DetectTheme(r *http.Request) string {
	return theme.DetectTheme(r)
}

// GetThemeCSS returns CSS for the specified theme
func GetThemeCSS(theme string) string {
	switch theme {
	case "light":
		return `
			body {
				background-color: #ffffff;
				color: #000000;
			}
			.graphiql-container {
				--color-primary: 40, 130, 250;
				--color-secondary: 110, 110, 110;
			}
		`
	case "dark":
		return `
			body {
				background-color: #1a1a1a;
				color: #ffffff;
			}
			.graphiql-container {
				--color-primary: 100, 180, 255;
				--color-secondary: 180, 180, 180;
				--color-base: 26, 26, 26;
			}
		`
	case "auto":
		return `
			@media (prefers-color-scheme: dark) {
				body {
					background-color: #1a1a1a;
					color: #ffffff;
				}
				.graphiql-container {
					--color-primary: 100, 180, 255;
					--color-secondary: 180, 180, 180;
					--color-base: 26, 26, 26;
				}
			}
			@media (prefers-color-scheme: light) {
				body {
					background-color: #ffffff;
					color: #000000;
				}
				.graphiql-container {
					--color-primary: 40, 130, 250;
					--color-secondary: 110, 110, 110;
				}
			}
		`
	default:
		return ""
	}
}

