package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestDiscoverCLIReleaseAndUpdateCheck(t *testing.T) {
	digest := sha256.Sum256([]byte("binary"))
	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/autodiscover" {
			http.NotFound(w, r)
			return
		}
		gotAuthorization = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"cli_versions":    map[string]any{runtime.GOOS + "-" + runtime.GOARCH: map[string]string{"version": "2.3.4", "sha256": hex.EncodeToString(digest[:])}},
				"cli_min_version": "2.0.0",
			},
		})
	}))
	defer server.Close()

	release, minimum, err := discoverCLIRelease(server.URL, "usr_update_test", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "2.3.4" || release.SHA256 != hex.EncodeToString(digest[:]) || minimum != "2.0.0" {
		t.Fatalf("discovered release = %#v minimum=%q", release, minimum)
	}
	if gotAuthorization != "Bearer usr_update_test" {
		t.Fatalf("autodiscover authorization = %q", gotAuthorization)
	}

	var stdout, stderr strings.Builder
	code, updated := checkAndUpdateCLI(server.URL, "usr_update_test", "check", nil, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || updated || !strings.Contains(stdout.String(), "CLI update available") {
		t.Fatalf("update check = code %d updated=%t stdout=%q stderr=%q", code, updated, stdout.String(), stderr.String())
	}
}

func TestCLIUpdateVersionComparisonAndAtomicReplacement(t *testing.T) {
	if compareSemver("1.2.4", "1.2.3") <= 0 || compareSemver("1.2.3-rc.1", "1.2.3") >= 0 || compareSemver("1.2.3", "1.2.3+build.2") != 0 {
		t.Fatal("semantic version comparison did not follow release precedence")
	}
	if _, ok := parseSemver("not-a-version"); ok {
		t.Fatal("invalid version parsed successfully")
	}

	directory := cliUpdateTestTempDir(t)
	target := filepath.Join(directory, "casspeed-cli")
	source := filepath.Join(directory, "cli.update.tmp")
	if err := os.WriteFile(target, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("verified new binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceCLIExecutable(source, target); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "verified new binary" {
		t.Fatalf("replaced binary = %q, %v", contents, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("replacement permissions = %v, %v", info, err)
	}
}

func cliUpdateTestTempDir(t *testing.T) string {
	t.Helper()
	org, name := moduleOrgAndName()
	base := filepath.Join(os.TempDir(), org)
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove CLI update temp dir: %v", err)
		}
	})
	return directory
}

func TestExecuteHealthHistoryAndShare(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer usr_test" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			if r.URL.Path != "/api/v1/speed-tests/test%2Fone/shares" && r.URL.Path != "/api/v1/speed-tests/test/one/shares" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"ok":true,"data":{"url":"/shares/code"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"data":[]}`)
	}))
	defer server.Close()

	for _, command := range []string{"health", "history", "share"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr strings.Builder
			args := []string(nil)
			if command == "share" {
				args = []string{"test/one"}
			}
			if code := execute(command, args, clientOptions{serverURL: server.URL, token: "usr_test", output: "json"}, &stdout, &stderr); code != 0 {
				t.Fatalf("execute returned %d: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), `"ok":true`) {
				t.Fatalf("unexpected output: %s", stdout.String())
			}
		})
	}
}

func TestClientTokenFileSecurityAndResolution(t *testing.T) {
	t.Setenv("CASSPEED_TOKEN", "usr_environment")
	if token, err := resolveToken("usr_explicit", "ignored"); err != nil || token != "usr_explicit" {
		t.Fatalf("explicit token = %q, %v", token, err)
	}
	if token, err := resolveToken("", ""); err != nil || token != "usr_environment" {
		t.Fatalf("environment token = %q, %v", token, err)
	}
	path := filepath.Join(t.TempDir(), "private", "token")
	if err := writePrivateToken(path, " usr_saved "); err != nil {
		t.Fatal(err)
	}
	if token, err := readPrivateToken(path); err != nil || token != "usr_saved" {
		t.Fatalf("saved token = %q, %v", token, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("token permissions = %v, %v", info, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(path); err == nil {
		t.Fatal("readPrivateToken accepted a group-readable token")
	}
	if err := writePrivateToken(path, " "); err == nil {
		t.Fatal("writePrivateToken accepted an empty token")
	}
}

func TestMeasureLatencyAndTransfer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
			return
		}
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := server.Client()
	ping, _, loss := measureLatency(base, client)
	if ping <= 0 || loss != 0 {
		t.Fatalf("latency measurements = ping %f, loss %f", ping, loss)
	}
	if got := measureTransfer(base, client, "test/id", "download", 10*time.Millisecond); got <= 0 {
		t.Fatalf("download throughput = %f", got)
	}
	if got := measureTransfer(base, client, "test/id", "upload", 10*time.Millisecond); got <= 0 {
		t.Fatalf("upload throughput = %f", got)
	}
}

func TestRunSpeedTestSubmitsWebSocketResult(t *testing.T) {
	var server *httptest.Server
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/speed-tests":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true,"data":{"test_id":"id-1","duration_seconds":1}}`)
		case "/healthz":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/speed-tests/id-1/download":
			_, _ = w.Write(make([]byte, 128))
		case "/api/v1/speed-tests/id-1/uploads":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
		case "/api/v1/speed-tests/id-1/status":
			connection, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			var result map[string]any
			if connection.ReadJSON(&result) == nil {
				_ = connection.WriteJSON(map[string]any{"stage": "complete"})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	jar, _ := cookiejar.New(nil)
	client := server.Client()
	request := func(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, base.String()+path, body)
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}
	result, err := runSpeedTest(base, client, jar, "", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.TestID != "id-1" {
		t.Fatalf("test id = %q", result.TestID)
	}
}

func TestWriteResponseAndBearerTransport(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	var stdout, stderr strings.Builder
	if code := writeResponse(response, "table", &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "ok") {
		t.Fatalf("writeResponse returned %d: output=%q error=%q", code, stdout.String(), stderr.String())
	}
	response = &http.Response{StatusCode: http.StatusBadRequest, Status: "400 Bad Request", Body: io.NopCloser(strings.NewReader(`{"message":"bad request"}`))}
	stdout.Reset()
	stderr.Reset()
	if code := writeResponse(response, "json", &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "bad request") {
		t.Fatalf("writeResponse error returned %d: %q", code, stderr.String())
	}
	transport := bearerTransport{base: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer usr_test" {
			t.Fatalf("authorization header = %q", request.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	}), token: "usr_test"}
	request, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
