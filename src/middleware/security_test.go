package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is a simple handler that writes 200 OK so we can confirm the chain continued.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// recordPathHandler captures the path seen by the next handler after middleware.
func recordPathHandler(seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
}

// ---- URLNormalizeMiddleware tests ----------------------------------------

func TestURLNormalizeMiddleware_Root(t *testing.T) {
	// Root "/" must pass through without redirect.
	handler := URLNormalizeMiddleware(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("root: got %d, want 200", rr.Code)
	}
}

func TestURLNormalizeMiddleware_TrailingSlash(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		query    string
		wantCode int
		wantLoc  string
	}{
		{
			name:     "trailing slash without query",
			path:     "/about/",
			wantCode: http.StatusMovedPermanently,
			wantLoc:  "/about",
		},
		{
			name:     "trailing slash with query",
			path:     "/about/",
			query:    "foo=bar",
			wantCode: http.StatusMovedPermanently,
			wantLoc:  "/about?foo=bar",
		},
		{
			name:     "no trailing slash passes through",
			path:     "/about",
			wantCode: http.StatusOK,
		},
		{
			// The last segment after the trailing "/" is empty (no "."),
			// so the middleware still issues a 301 redirect here.
			name:     "path ending with file extension still redirects trailing slash",
			path:     "/static/app.js/",
			wantCode: http.StatusMovedPermanently,
			wantLoc:  "/static/app.js",
		},
		{
			name:     "nested trailing slash redirects",
			path:     "/a/b/c/",
			wantCode: http.StatusMovedPermanently,
			wantLoc:  "/a/b/c",
		},
	}

	handler := URLNormalizeMiddleware(okHandler)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.path
			if tc.query != "" {
				target += "?" + tc.query
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rr.Code, tc.wantCode)
			}
			if tc.wantLoc != "" {
				loc := rr.Header().Get("Location")
				if loc != tc.wantLoc {
					t.Errorf("Location = %q, want %q", loc, tc.wantLoc)
				}
			}
		})
	}
}

// ---- SecurityHeaders tests -----------------------------------------------

func TestSecurityHeaders_NoSSL(t *testing.T) {
	handler := SecurityHeaders(false)(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	required := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "SAMEORIGIN",
		"X-Xss-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, want := range required {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
	// HSTS must NOT be set when SSL is disabled
	if hsts := rr.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS should not be set when SSL disabled, got %q", hsts)
	}
}

func TestSecurityHeaders_WithSSL(t *testing.T) {
	handler := SecurityHeaders(true)(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if hsts := rr.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS header should be set when SSL is enabled")
	}
}

// ---- PathSecurityMiddleware tests ----------------------------------------

func TestPathSecurityMiddleware_Traversal(t *testing.T) {
	handler := PathSecurityMiddleware(okHandler)

	traversalCases := []string{
		"/../etc/passwd",
		"/foo/../bar",
		"/foo/../../etc",
	}

	for _, p := range traversalCases {
		t.Run("blocks "+p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("path %q: got %d, want 400", p, rr.Code)
			}
		})
	}
}

func TestPathSecurityMiddleware_EncodedTraversal(t *testing.T) {
	handler := PathSecurityMiddleware(okHandler)

	// Simulate %2e%2e in the raw path
	req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
	req.URL.RawPath = "/foo/%2e%2e/bar"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("encoded traversal: got %d, want 400", rr.Code)
	}
}

func TestPathSecurityMiddleware_SafePaths(t *testing.T) {
	handler := PathSecurityMiddleware(okHandler)

	safePaths := []string{
		"/",
		"/about",
		"/api/v1/results",
		"/static/app.js",
	}

	for _, p := range safePaths {
		t.Run("allows "+p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("path %q: got %d, want 200", p, rr.Code)
			}
		})
	}
}

func TestPathSecurityMiddleware_NormalizesPath(t *testing.T) {
	// A path like /foo//bar should be cleaned to /foo/bar.
	var seen string
	handler := PathSecurityMiddleware(recordPathHandler(&seen))
	req := httptest.NewRequest(http.MethodGet, "/foo//bar", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if seen != "/foo/bar" {
		t.Errorf("normalized path = %q, want /foo/bar", seen)
	}
}

func TestPathSecurityMiddleware_PreservesTrailingSlash(t *testing.T) {
	// A trailing slash on an original path should be preserved post-clean.
	var seen string
	handler := PathSecurityMiddleware(recordPathHandler(&seen))
	req := httptest.NewRequest(http.MethodGet, "/foo/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if seen != "/foo/" {
		t.Errorf("path after middleware = %q, want /foo/", seen)
	}
}
