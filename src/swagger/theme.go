package swagger

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
			.swagger-ui .topbar {
				background-color: #f0f0f0;
			}
		`
	case "dark":
		return `
			body {
				background-color: #1a1a1a;
				color: #ffffff;
			}
			.swagger-ui .topbar {
				background-color: #2a2a2a;
			}
			.swagger-ui {
				filter: invert(88%) hue-rotate(180deg);
			}
			.swagger-ui .renderedMarkdown code,
			.swagger-ui .response .microlight {
				filter: invert(100%) hue-rotate(180deg);
			}
		`
	case "auto":
		return `
			@media (prefers-color-scheme: dark) {
				body {
					background-color: #1a1a1a;
					color: #ffffff;
				}
				.swagger-ui .topbar {
					background-color: #2a2a2a;
				}
				.swagger-ui {
					filter: invert(88%) hue-rotate(180deg);
				}
				.swagger-ui .renderedMarkdown code,
				.swagger-ui .response .microlight {
					filter: invert(100%) hue-rotate(180deg);
				}
			}
			@media (prefers-color-scheme: light) {
				body {
					background-color: #ffffff;
					color: #000000;
				}
				.swagger-ui .topbar {
					background-color: #f0f0f0;
				}
			}
		`
	default:
		return ""
	}
}
