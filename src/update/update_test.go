package update

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func withHTTPTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous })
}

// ---- NewService tests ----------------------------------------------------

func TestNewService_StoresConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		RepoOwner:  "casapps",
		RepoName:   "casspeed",
		Branch:     "main",
		CurrentVer: "1.2.3",
	}
	svc := NewService(cfg)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.config != cfg {
		t.Error("config not stored correctly")
	}
}

// ---- GetCurrentVersion tests ---------------------------------------------

func TestGetCurrentVersion(t *testing.T) {
	svc := NewService(&Config{CurrentVer: "2.0.0"})
	if got := svc.GetCurrentVersion(); got != "2.0.0" {
		t.Errorf("GetCurrentVersion() = %q, want '2.0.0'", got)
	}
}

func TestGetCurrentVersion_Empty(t *testing.T) {
	svc := NewService(&Config{})
	if got := svc.GetCurrentVersion(); got != "" {
		t.Errorf("GetCurrentVersion() = %q, want empty", got)
	}
}

// ---- GetBranch / SetBranch tests ----------------------------------------

func TestGetBranch_Default(t *testing.T) {
	svc := NewService(&Config{Branch: "main"})
	if got := svc.GetBranch(); got != "main" {
		t.Errorf("GetBranch() = %q, want 'main'", got)
	}
}

func TestSetBranch(t *testing.T) {
	svc := NewService(&Config{Branch: "main"})
	svc.SetBranch("develop")
	if got := svc.GetBranch(); got != "develop" {
		t.Errorf("GetBranch() after SetBranch = %q, want 'develop'", got)
	}
}

// ---- getAssetName tests --------------------------------------------------

func TestGetAssetName_ContainsPlatform(t *testing.T) {
	svc := NewService(&Config{})
	name := svc.getAssetName()

	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("asset name %q should contain OS %q", name, runtime.GOOS)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("asset name %q should contain arch %q", name, runtime.GOARCH)
	}
}

func TestGetAssetName_StartsWithBinaryName(t *testing.T) {
	svc := NewService(&Config{})
	name := svc.getAssetName()
	if !strings.HasPrefix(name, "casspeed-") {
		t.Errorf("asset name %q should start with 'casspeed-'", name)
	}
}

// ---- CheckForUpdates when disabled --------------------------------------

func TestCheckForUpdates_Disabled(t *testing.T) {
	svc := NewService(&Config{Enabled: false})
	_, err := svc.CheckForUpdates()
	if err == nil {
		t.Error("expected error when updates are disabled")
	}
}

func TestCheckForUpdates_FindsCurrentPlatformAsset(t *testing.T) {
	svc := NewService(&Config{Enabled: true, RepoOwner: "example", RepoName: "casspeed", CurrentVer: "1.0.0"})
	payload, err := json.Marshal(map[string]interface{}{
		"tag_name":     "v1.2.0",
		"body":         "Bug fixes",
		"published_at": "2025-01-02T03:04:05Z",
		"assets": []map[string]string{{
			"name":                 svc.getAssetName(),
			"browser_download_url": "https://downloads.example/casspeed",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	withHTTPTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.github.com" {
			t.Errorf("request host = %q, want api.github.com", req.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(payload))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}))

	release, err := svc.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if release.Version != "1.2.0" || release.DownloadURL != "https://downloads.example/casspeed" || release.Changelog != "Bug fixes" {
		t.Errorf("release = %#v", release)
	}
}

func TestCheckForUpdatesRejectsBadResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP failure", status: http.StatusServiceUnavailable, body: `{}`},
		{name: "invalid JSON", status: http.StatusOK, body: `{`},
		{name: "missing platform asset", status: http.StatusOK, body: `{"tag_name":"v2","assets":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withHTTPTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tt.status,
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}))
			svc := NewService(&Config{Enabled: true, RepoOwner: "example", RepoName: "casspeed"})
			if _, err := svc.CheckForUpdates(); err == nil {
				t.Fatal("CheckForUpdates should reject invalid release responses")
			}
		})
	}
}

func TestCheckForUpdatesTransportFailure(t *testing.T) {
	withHTTPTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection unavailable")
	}))
	svc := NewService(&Config{Enabled: true, RepoOwner: "example", RepoName: "casspeed"})
	if _, err := svc.CheckForUpdates(); err == nil || !strings.Contains(err.Error(), "connection unavailable") {
		t.Fatalf("CheckForUpdates error = %v, want transport failure", err)
	}
}

// ---- copyFile tests -----------------------------------------------------

func TestCopyFile_CopiesContent(t *testing.T) {
	src := t.TempDir() + "/src.bin"
	dst := t.TempDir() + "/dst.bin"

	if err := os.WriteFile(src, []byte("hello casspeed"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello casspeed" {
		t.Errorf("copyFile content = %q, want 'hello casspeed'", string(got))
	}
}

func TestCopyFile_MissingSource(t *testing.T) {
	err := copyFile("/nonexistent/src.bin", t.TempDir()+"/dst.bin")
	if err == nil {
		t.Error("expected error for missing source file")
	}
}

func TestCopyFile_BadDestination(t *testing.T) {
	src := t.TempDir() + "/src.bin"
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := copyFile(src, "/nonexistent/path/dst.bin")
	if err == nil {
		t.Error("expected error for invalid destination path")
	}
}

func TestReplaceBinarySuccess(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "casspeed")
	newBinary := filepath.Join(dir, "casspeed-new")
	if err := os.WriteFile(current, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newBinary, []byte("new"), 0750); err != nil {
		t.Fatal(err)
	}

	svc := NewService(&Config{BinaryPath: current})
	if err := svc.replaceBinary(newBinary); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	data, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Errorf("installed binary = %q, want new", data)
	}
	if _, err := os.Stat(current + ".backup"); !os.IsNotExist(err) {
		t.Errorf("backup should be removed after success, stat error = %v", err)
	}
}

func TestReplaceBinaryBackupFailureLeavesCurrentPathUntouched(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "missing-casspeed")
	newBinary := filepath.Join(dir, "casspeed-new")
	if err := os.WriteFile(newBinary, []byte("new"), 0700); err != nil {
		t.Fatal(err)
	}
	svc := NewService(&Config{BinaryPath: current})
	if err := svc.replaceBinary(newBinary); err == nil {
		t.Fatal("replaceBinary should fail when it cannot back up the current binary")
	}
	if _, err := os.Stat(current); !os.IsNotExist(err) {
		t.Errorf("current path should remain absent after backup failure, stat error = %v", err)
	}
	if _, err := os.Stat(newBinary); err != nil {
		t.Errorf("new binary should remain available after backup failure: %v", err)
	}
}

func TestReplaceBinaryRestoresBackupAfterCopyFailure(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "casspeed")
	if err := os.WriteFile(current, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}

	svc := NewService(&Config{BinaryPath: current})
	if err := svc.replaceBinary(filepath.Join(dir, "missing-binary")); err == nil {
		t.Fatal("replaceBinary should fail when the update file is missing")
	}
	data, err := os.ReadFile(current)
	if err != nil {
		t.Fatalf("current binary should be restored: %v", err)
	}
	if string(data) != "old" {
		t.Errorf("restored binary = %q, want old", data)
	}
}

func TestVerifyBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test binary scripts require a Unix shell")
	}
	path := filepath.Join(t.TempDir(), "version-check")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'casspeed v1.0.0'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := NewService(&Config{}).verifyBinary(path); err != nil {
		t.Errorf("verifyBinary accepted output should succeed: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho unrelated\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := NewService(&Config{}).verifyBinary(path); err == nil {
		t.Error("verifyBinary should reject output without casspeed identity")
	}
}
