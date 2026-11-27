package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTOTPSecretEncryptionRoundTripAndAuthentication(t *testing.T) {
	s := &Server{encryptionKey: bytes.Repeat([]byte{7}, 32)}
	secret := []byte("JBSWY3DPEHPK3PXP")
	encoded, err := s.encryptTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) == encoded {
		t.Fatal("encrypted secret was stored in plaintext")
	}
	decoded, err := s.decryptTOTPSecret(encoded)
	if err != nil || !bytes.Equal(decoded, secret) {
		t.Fatalf("decryptTOTPSecret() = %q, %v; want original secret", decoded, err)
	}
	other := &Server{encryptionKey: bytes.Repeat([]byte{8}, 32)}
	if _, err := other.decryptTOTPSecret(encoded); err == nil {
		t.Fatal("ciphertext authenticated under a different key")
	}
	if _, err := s.decryptTOTPSecret("not-base64!"); err == nil {
		t.Fatal("malformed ciphertext was accepted")
	}
}

func TestMFARequestDecoderRejectsUnknownAndOversizedInput(t *testing.T) {
	for _, body := range []string{`{"code":"123456","unexpected":true}`, strings.Repeat("x", 4097)} {
		r := httptest.NewRequest("POST", "/server/auth/2fa", strings.NewReader(body))
		w := httptest.NewRecorder()
		var request struct {
			Code string `json:"code"`
		}
		if err := decodeMFARequest(w, r, &request); err == nil {
			t.Fatalf("decodeMFARequest accepted invalid body of %d bytes", len(body))
		}
	}
}

func TestRecoveryCodeHashNormalizesUserInput(t *testing.T) {
	first := recoveryCodeHash(" ABCD-1234 ")
	if got := recoveryCodeHash("abcd1234"); got != first {
		t.Fatalf("normalized recovery hashes differ: %q != %q", first, got)
	}
	if got := hashRecoveryCodes([]string{"ABCD-1234", "OTHER"}); len(got) != 2 || got[0] != first || got[0] == got[1] {
		t.Fatalf("hashRecoveryCodes() = %#v", got)
	}
}

func TestMFAChallengePagesAndMalformedRequests(t *testing.T) {
	s := minimalServer()
	for _, test := range []struct {
		path    string
		handler http.HandlerFunc
		want    string
	}{
		{"/server/auth/2fa", s.handleMFAChallenge, "Authenticator"},
		{"/server/auth/recovery/use", s.handleMFARecovery, "recovery"},
	} {
		t.Run(test.path, func(t *testing.T) {
			page := httptest.NewRecorder()
			test.handler(page, httptest.NewRequest(http.MethodGet, test.path, nil))
			if page.Code != http.StatusOK || !strings.Contains(strings.ToLower(page.Body.String()), strings.ToLower(test.want)) {
				t.Fatalf("challenge page response = %d: %s", page.Code, page.Body.String())
			}
			badJSON := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(`{"partial_token":"x","unknown":true}`))
			badJSON.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			test.handler(response, badJSON)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Header().Get("Content-Type"), "application/json") {
				t.Errorf("malformed API request response = %d %s", response.Code, response.Body.String())
			}
			badForm := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader("partial_token=x&code=000000"))
			badForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response = httptest.NewRecorder()
			test.handler(response, badForm)
			if response.Code != http.StatusForbidden {
				t.Errorf("cross-origin form submission status = %d, want 403", response.Code)
			}
		})
	}
}
