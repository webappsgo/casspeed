package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/i2p"
)

func TestAutodiscoverPublishesOnlyThePublicClientContract(t *testing.T) {
	t.Setenv("DOMAIN", "https://speed.example.test,https://second.example.test,localhost,10.0.0.4")
	s := minimalServer()
	s.Config.Server.APIVersion = "v2"
	s.Config.Server.Update.CLIMinVersion = "1.0.0"
	s.Config.Server.Update.AgentMinVersion = "2.0.0"
	s.version = "1.2.3"
	s.DataDir = t.TempDir()
	cliDir := filepath.Join(s.DataDir, "cli")
	if err := os.MkdirAll(cliDir, 0700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("verified-cli-binary")
	binaryName := "casspeed-cli-linux-amd64"
	if err := os.WriteFile(filepath.Join(cliDir, binaryName), binary, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	if err := os.WriteFile(filepath.Join(cliDir, "version.txt"), []byte("1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cliDir, "sha256.txt"), []byte(hex.EncodeToString(digest[:])+"  "+binaryName+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://speed.example.test/api/autodiscover", nil)
	response := httptest.NewRecorder()
	s.handleAPIAutodiscover(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("autodiscover response = %d headers=%v", response.Code, response.Header())
	}
	var envelope struct {
		OK   bool           `json:"ok"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || !envelope.OK {
		t.Fatalf("invalid autodiscover envelope: %s (%v)", response.Body.String(), err)
	}
	if envelope.Data["version"] != "1.2.3" || envelope.Data["name"] != "CasSpeed" {
		t.Fatalf("autodiscover identity fields = %#v", envelope.Data)
	}
	api, ok := envelope.Data["api"].(map[string]any)
	if !ok || api["current_version"] != "v2" {
		t.Fatalf("API version missing from autodiscover: %#v", envelope.Data["api"])
	}
	cliVersions, ok := envelope.Data["cli_versions"].(map[string]any)
	if !ok || cliVersions["linux-amd64"] == nil || envelope.Data["cli_min_version"] != "1.0.0" {
		t.Fatalf("verified CLI version catalog or minimum version missing: %#v", envelope.Data)
	}
	if envelope.Data["agent_min_version"] != "2.0.0" {
		t.Fatalf("agent minimum version missing: %#v", envelope.Data["agent_min_version"])
	}
	urls, ok := envelope.Data["urls"].([]any)
	if !ok || len(urls) != 2 || urls[0] != "https://speed.example.test" || urls[1] != "https://second.example.test" {
		t.Fatalf("public URL list = %#v", envelope.Data["urls"])
	}
	for _, forbidden := range []string{"admin_path", "config_schema", "options", "server.token", "localhost", "10.0.0.4"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Errorf("autodiscover leaked forbidden value %q: %s", forbidden, response.Body.String())
		}
	}
	for _, field := range []string{"cli_versions", "cli_min_version", "agent_versions", "agent_min_version"} {
		if _, exists := envelope.Data[field]; !exists {
			t.Errorf("autodiscover is missing %q", field)
		}
	}
}

func TestAutodiscoverTorResponseOmitsClearnetOrigins(t *testing.T) {
	t.Setenv("DOMAIN", "https://clearnet.example,https://another.example")
	s := minimalServer()
	request := httptest.NewRequest(http.MethodGet, "http://casspeedexample.onion/api/autodiscover", nil)
	request = request.WithContext(context.WithValue(request.Context(), overlayRequestKey{}, "tor"))

	urls := s.autodiscoverURLs(request)
	if len(urls) != 1 || urls[0] != "http://casspeedexample.onion" {
		t.Fatalf("Tor autodiscover origins = %#v, want only the onion origin", urls)
	}
}

func TestBinaryVersionCatalogSkipsChecksumMismatchAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	valid := []byte("valid-binary")
	if err := os.WriteFile(filepath.Join(directory, "version.txt"), []byte("3.1.4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "casspeed-cli-linux-amd64"), valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "casspeed-cli-darwin-arm64"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(valid)
	checksums := hex.EncodeToString(digest[:]) + "  casspeed-cli-linux-amd64\n" + strings.Repeat("0", 64) + "  casspeed-cli-darwin-arm64\n"
	if err := os.WriteFile(filepath.Join(directory, "sha256.txt"), []byte(checksums), 0600); err != nil {
		t.Fatal(err)
	}
	s := minimalServer()
	catalog := s.readBinaryVersionCatalog(directory, "casspeed-cli-")
	if len(catalog) != 1 || catalog["linux-amd64"]["version"] != "3.1.4" || catalog["linux-amd64"]["sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("version catalog = %#v", catalog)
	}
}

func TestPublicOriginRejectsPrivateHostsAndPaths(t *testing.T) {
	for _, value := range []string{"http://localhost", "http://127.0.0.1", "https://192.168.1.10", "https://service.internal", "https://example.test/path", "https://user@example.test", "file:///etc/passwd"} {
		if _, ok := publicOrigin(value); ok {
			t.Errorf("publicOrigin(%q) accepted a non-public origin", value)
		}
	}
	if got, ok := publicOrigin("https://EXAMPLE.test:443/"); !ok || got != "https://example.test" {
		t.Fatalf("publicOrigin() = %q, %t", got, ok)
	}
	if got, ok := publicOrigin("https://[2001:4860:4860::8888]"); !ok || got != "https://[2001:4860:4860::8888]" {
		t.Fatalf("publicOrigin(IPv6) = %q, %t", got, ok)
	}
}

func TestAutodiscoverPublishesOnlyExposedHealthyI2PAddress(t *testing.T) {
	s := minimalServer()
	s.Config.Server.I2P.Expose = true
	s.i2pState = i2p.State{Enabled: true, Running: true, Status: "running", Provider: i2p.ProviderSAM, EepsiteAddress: "abc.b32.i2p"}
	response := httptest.NewRecorder()
	s.handleAPIAutodiscover(response, httptest.NewRequest(http.MethodGet, "https://service.example.test/api/autodiscover", nil))
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data["i2p"] != "abc.b32.i2p" {
		t.Fatalf("exposed I2P address = %#v", payload.Data["i2p"])
	}

	s.i2pState = i2p.State{Enabled: true, Status: "starting", Provider: i2p.ProviderSAM}
	response = httptest.NewRecorder()
	s.handleAPIAutodiscover(response, httptest.NewRequest(http.MethodGet, "https://service.example.test/api/autodiscover", nil))
	if strings.Contains(response.Body.String(), "\"i2p\"") {
		t.Fatalf("autodiscover published an unavailable I2P address: %s", response.Body.String())
	}
}
