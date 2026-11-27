package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
)

func TestConfiguredTrackingProviders(t *testing.T) {
	tests := []struct {
		name       string
		config     config.TrackingConfig
		want, body bool
	}{
		{"disabled", config.TrackingConfig{Type: "none"}, false, false},
		{"google ga4", config.TrackingConfig{Type: "google", ID: "G-ABC123"}, true, true},
		{"matomo", config.TrackingConfig{Type: "matomo", ID: "1", URL: "https://metrics.example"}, true, true},
		{"owa", config.TrackingConfig{Type: "owa", ID: "site", URL: "https://metrics.example"}, true, true},
		{"fathom", config.TrackingConfig{Type: "fathom", ID: "site"}, true, false},
		{"plausible", config.TrackingConfig{Type: "plausible", ID: "example.org"}, true, false},
		{"umami", config.TrackingConfig{Type: "umami", ID: "12345678-1234-1234-1234-123456789abc", URL: "https://metrics.example"}, true, false},
		{"simple", config.TrackingConfig{Type: "simple"}, true, false},
		{"cloudflare", config.TrackingConfig{Type: "cloudflare", ID: "token"}, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := configuredTracking(test.config)
			if (got.tags != "") != test.want {
				t.Fatalf("provider markup presence = %t, want %t", got.tags != "", test.want)
			}
			if (got.body != "") != test.body {
				t.Fatalf("same-origin script presence = %t, want %t", got.body != "", test.body)
			}
			if got.body != "" && strings.Contains(got.body, "</script>") {
				t.Fatal("generated JavaScript contains a closing script tag")
			}
		})
	}
}

func TestTrackingRequiresAnalyticsConsentAndAvoidsOverlayNetworks(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Tracking = config.TrackingConfig{Type: "google", ID: "G-ABC123"}
	s := &Server{Config: cfg}
	r := httptest.NewRequest("GET", "https://example.org/", nil)
	if s.trackingAllowed(r) {
		t.Fatal("tracking allowed without consent")
	}
	r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: `%7B%22analytics%22%3Atrue%2C%22timestamp%22%3A1%7D`})
	if !s.trackingAllowed(r) {
		t.Fatal("tracking not allowed after analytics consent")
	}
	r.Host = "example.onion"
	if s.trackingAllowed(r) {
		t.Fatal("tracking allowed on onion host")
	}
	r.Host = "example.i2p"
	if s.trackingAllowed(r) {
		t.Fatal("tracking allowed on I2P host")
	}
}

func TestAPIVersionMiddlewareMapsConfiguredPrefix(t *testing.T) {
	cfg := config.Default()
	cfg.Server.APIVersion = "v2"
	s := &Server{Config: cfg}
	handler := s.apiVersionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/resource" {
			t.Errorf("internal path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_content":"/api/v1/resource"}`))
	}))
	request := httptest.NewRequest("GET", "/api/v2/resource", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("v2 response status = %d", recorder.Code)
	}
	if got := recorder.Body.String(); !strings.Contains(got, `"user_content":"/api/v1/resource"`) {
		t.Fatalf("API middleware changed arbitrary response content: %s", got)
	}
	wrongVersion := httptest.NewRecorder()
	handler.ServeHTTP(wrongVersion, httptest.NewRequest("GET", "/api/v1/resource", nil))
	if wrongVersion.Code != http.StatusNotFound {
		t.Fatalf("unconfigured version status = %d, want 404", wrongVersion.Code)
	}
}
