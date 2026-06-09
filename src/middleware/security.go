package middleware

import (
	"net/http"
	"path"
	"strings"
)

// URLNormalizeMiddleware removes trailing slashes (except root "/") and redirects
// to canonical URL with 301. Must run first in the middleware chain. (PART 16)
func URLNormalizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path

		// Root stays as-is
		if p == "/" {
			next.ServeHTTP(w, r)
			return
		}

		// Remove trailing slash unless path ends with a file extension
		if strings.HasSuffix(p, "/") {
			last := p[strings.LastIndex(p, "/"):]
			if !strings.Contains(last, ".") {
				canonical := strings.TrimSuffix(p, "/")
				if r.URL.RawQuery != "" {
					canonical += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, canonical, http.StatusMovedPermanently)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds security headers to all responses per PART 11 specification
func SecurityHeaders(sslEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Required security headers (PART 11)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// HSTS when SSL is enabled
			if sslEnabled {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PathSecurityMiddleware normalizes paths and blocks traversal attempts (PART 5)
// This middleware MUST be first in the chain - before auth, before routing
func PathSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original := r.URL.Path

		// Check both raw path and URL-decoded for traversal
		rawPath := r.URL.RawPath
		if rawPath == "" {
			rawPath = r.URL.Path
		}

		// Block path traversal attempts (encoded and decoded)
		// %2e = . so %2e%2e = ..
		if strings.Contains(original, "..") ||
			strings.Contains(rawPath, "..") ||
			strings.Contains(strings.ToLower(rawPath), "%2e") {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Normalize the path
		cleaned := path.Clean(original)

		// Ensure leading slash
		if !strings.HasPrefix(cleaned, "/") {
			cleaned = "/" + cleaned
		}

		// Preserve trailing slash for directory paths
		if original != "/" && strings.HasSuffix(original, "/") && !strings.HasSuffix(cleaned, "/") {
			cleaned += "/"
		}

		// Update request
		r.URL.Path = cleaned

		next.ServeHTTP(w, r)
	})
}
