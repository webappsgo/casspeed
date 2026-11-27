package server

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/tor"
)

func TestTorVanityImportAcceptsSecretKeyOnly(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	expanded := sha512.Sum512(seed)
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	secretFile := append([]byte("== ed25519v1-secret: type0 ==\x00"), expanded[:]...)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("hs_ed25519_secret_key", "hs_ed25519_secret_key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(secretFile); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	s := minimalServer()
	s.DataDir = dataDir
	s.torVanity = tor.NewVanityManager(dataDir)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/server/administration/network/tor/import", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	s.handleTorVanityImport(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("secret-only import status = %d, body=%s", response.Code, response.Body.String())
	}
	var result struct {
		OK       bool   `json:"ok"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if !result.OK || len(strings.TrimSuffix(result.Hostname, ".onion")) != 56 || !strings.HasSuffix(result.Hostname, ".onion") {
		t.Fatalf("secret-only import result = %#v", result)
	}
	if candidates := s.torVanity.Candidates(); len(candidates) != 1 || candidates[0] != result.Hostname {
		t.Fatalf("stored candidates = %#v, want [%q]", candidates, result.Hostname)
	}
}
