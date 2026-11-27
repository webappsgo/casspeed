package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/config"
)

func TestTorAdminAPIRendersValidatesAndPersistsConfiguration(t *testing.T) {
	s := minimalServer()
	s.ConfigPath = filepath.Join(t.TempDir(), "config", "server.yml")
	s.DataDir = filepath.Join(t.TempDir(), "data")
	s.LogDir = filepath.Join(t.TempDir(), "logs")
	candidate := s.Config.Server.Tor
	encoded, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	call := func(handler http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "/api/v1/server/administration/network/tor", strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler(response, request)
		return response
	}
	if response := call(s.handleTorAdminAPI, http.MethodGet, ""); response.Code != http.StatusOK {
		t.Fatalf("Tor config GET returned %d", response.Code)
	}
	if response := call(s.handleTorAdminValidate, http.MethodPost, string(encoded)); response.Code != http.StatusOK {
		t.Fatalf("valid Tor config validation returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(s.handleTorAdminValidate, http.MethodPost, `{}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid Tor config validation returned %d", response.Code)
	}
	if response := call(s.handleTorAdminAPI, http.MethodPatch, string(encoded)); response.Code != http.StatusOK {
		t.Fatalf("Tor config PATCH returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(s.handleTorAdminAPI, http.MethodPatch, `{`); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed Tor config returned %d", response.Code)
	}
	if response := call(s.handleTorAdminAPI, http.MethodPost, ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported Tor config method returned %d", response.Code)
	}
}

func TestI2PAdminAPIRendersValidatesAndPersistsConfiguration(t *testing.T) {
	s := minimalServer()
	s.ConfigPath = filepath.Join(t.TempDir(), "config", "server.yml")
	s.DataDir = filepath.Join(t.TempDir(), "data")
	s.LogDir = filepath.Join(t.TempDir(), "logs")
	candidate := s.Config.Server.I2P
	encoded, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	call := func(handler http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "/api/v1/server/administration/network/i2p", strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler(response, request)
		return response
	}
	if response := call(s.handleI2PAdminAPI, http.MethodGet, ""); response.Code != http.StatusOK {
		t.Fatalf("I2P config GET returned %d", response.Code)
	}
	if response := call(s.handleI2PAdminValidate, http.MethodPost, string(encoded)); response.Code != http.StatusOK {
		t.Fatalf("valid I2P config validation returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(s.handleI2PAdminValidate, http.MethodPost, `{}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid I2P config validation returned %d", response.Code)
	}
	if response := call(s.handleI2PAdminAPI, http.MethodPatch, string(encoded)); response.Code != http.StatusOK {
		t.Fatalf("I2P config PATCH returned %d: %s", response.Code, response.Body.String())
	}
	if response := call(s.handleI2PAdminAPI, http.MethodPatch, `{`); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed I2P config returned %d", response.Code)
	}
	if response := call(s.handleI2PAdminAPI, http.MethodPost, ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported I2P config method returned %d", response.Code)
	}
	if config.Default().Server.I2P.VirtualPort != candidate.VirtualPort {
		t.Fatal("test fixture no longer matches the default I2P port")
	}
}
