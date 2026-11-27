package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casapps/casspeed/src/i2p"
	"github.com/casapps/casspeed/src/tor"
)

func TestOverlayAdminHTTPErrorUsesRequestLanguage(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://service.b32.i2p/server/administration/network/i2p", nil)
	request = request.WithContext(context.WithValue(request.Context(), languageContextKey{}, "es"))
	if got, want := overlayAdminHTTPError(request, http.StatusForbidden), "No se pudo aceptar esta solicitud."; got != want {
		t.Fatalf("overlayAdminHTTPError() = %q, want %q", got, want)
	}
}

func TestTorHealthHostnameRequiresExposureOptIn(t *testing.T) {
	s := minimalServer()
	s.torState = tor.State{Enabled: true, Running: true, Status: "healthy", Hostname: "secret.onion"}
	if got := s.torHealth().Hostname; got != "" {
		t.Fatalf("hidden Tor hostname = %q, want empty", got)
	}
	s.Config.Server.Tor.Expose = true
	if got := s.torHealth().Hostname; got != "secret.onion" {
		t.Fatalf("exposed Tor hostname = %q, want secret.onion", got)
	}
}

func TestI2PHealthUsesFixedClientStatusContract(t *testing.T) {
	tests := []struct {
		name     string
		state    i2p.State
		enabled  bool
		expose   bool
		running  bool
		status   string
		hostname string
		provider string
	}{
		{name: "disabled", state: i2p.State{Status: "disabled"}, status: "disabled", provider: "none"},
		{name: "no provider", state: i2p.State{Enabled: true, Status: "no_provider"}, status: "disabled", provider: "none"},
		{name: "starting", state: i2p.State{Enabled: true, Status: "starting", Provider: i2p.ProviderSAM}, enabled: true, status: "starting", provider: "sam"},
		{name: "building", state: i2p.State{Enabled: true, Status: "building", Provider: i2p.ProviderI2PD}, enabled: true, status: "starting", provider: "i2pd"},
		{name: "running hidden", state: i2p.State{Enabled: true, Running: true, Status: "running", Provider: i2p.ProviderSAM, EepsiteAddress: "abc.b32.i2p"}, enabled: true, running: true, status: "healthy", provider: "sam"},
		{name: "running exposed", state: i2p.State{Enabled: true, Running: true, Status: "running", Provider: i2p.ProviderSAM, EepsiteAddress: "abc.b32.i2p"}, enabled: true, expose: true, running: true, status: "healthy", hostname: "abc.b32.i2p", provider: "sam"},
		{name: "error", state: i2p.State{Enabled: true, Status: "error", Provider: i2p.ProviderI2PD, Error: "private failure"}, enabled: true, status: "unavailable", provider: "i2pd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := minimalServer()
			s.i2pState = test.state
			s.Config.Server.I2P.Enabled = test.enabled
			s.Config.Server.I2P.Expose = test.expose
			got := s.i2PHealth()
			if got.Enabled != test.enabled || got.Running != test.running || got.Status != test.status || got.Hostname != test.hostname || got.Provider != test.provider {
				t.Fatalf("I2P health = %#v", got)
			}
			if got.State != test.state.Status {
				t.Fatalf("lifecycle state = %q, want %q", got.State, test.state.Status)
			}
		})
	}
}

func TestOverlayBuildURLIgnoresForwardedHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://service.b32.i2p/page", nil)
	request.Host = "service.b32.i2p"
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	handler := overlayRequestHandler("i2p", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := BuildURL(r, "/page"); got != "http://service.b32.i2p/page" {
			t.Errorf("BuildURL() = %q, want overlay origin", got)
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
}
