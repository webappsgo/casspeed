package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
)

func cliBinaryRequest(filename string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/cli/binaries/"+filename, nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("filename", filename)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
}

func TestCLIBinaryDownloadRequiresPublishedChecksum(t *testing.T) {
	s := minimalServer()
	directory := t.TempDir()
	s.Config.CLI.BinaryDownload.Dir = directory
	s.DataDir = t.TempDir()
	filename := "casspeed-cli-linux-amd64"
	binary := []byte("release binary")
	if err := os.WriteFile(filepath.Join(directory, filename), binary, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "version.txt"), []byte("1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	checksum := hex.EncodeToString(digest[:])
	if err := os.WriteFile(filepath.Join(directory, "sha256.txt"), []byte(checksum+"  "+filename+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	request := cliBinaryRequest(filename)
	response := httptest.NewRecorder()
	s.handleCLIBinaryDownload(response, request)
	if response.Code != http.StatusOK || response.Body.String() != string(binary) {
		t.Fatalf("download response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download security headers = %v", response.Header())
	}

	if err := os.WriteFile(filepath.Join(directory, "sha256.txt"), []byte(hex.EncodeToString(make([]byte, sha256.Size))+"  "+filename+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handleCLIBinaryDownload(response, cliBinaryRequest(filename))
	if response.Code != http.StatusNotFound {
		t.Fatalf("tampered catalog download status = %d, want 404", response.Code)
	}
}

func TestCLIBinaryDownloadAuthAndFilenamePolicy(t *testing.T) {
	s := minimalServer()
	s.Config.CLI.BinaryDownload.RequireAuth = true
	request := cliBinaryRequest("casspeed-cli-linux-amd64")
	response := httptest.NewRecorder()
	s.handleCLIBinaryDownload(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer status = %d, want 401", response.Code)
	}

	s.Config.CLI.BinaryDownload.RequireAuth = false
	request = cliBinaryRequest("../../secrets.yml")
	response = httptest.NewRecorder()
	s.handleCLIBinaryDownload(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("invalid filename status = %d, want 404", response.Code)
	}
}
