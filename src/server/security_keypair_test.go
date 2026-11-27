package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/store"
)

func TestSecurityKeypairEncryptDecryptAndRotateReports(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	configDir := t.TempDir()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	manager, err := NewSecurityKeypairManager(configDir, secret, "Casspeed", "security@example.net", db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := manager.Generate(ctx, now); err != nil {
		t.Fatalf("generate project key: %v", err)
	}
	fingerprint, err := manager.Fingerprint(ctx)
	if err != nil || fingerprint == "" {
		t.Fatalf("read project key fingerprint %q: %v", fingerprint, err)
	}
	plaintext := []byte(`{"summary":"private vulnerability"}`)
	ciphertext, err := manager.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt report: %v", err)
	}
	decrypted, err := manager.Decrypt(ciphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypt report %q: %v", decrypted, err)
	}
	if err := db.CreateSecurityReport(ctx, store.SecurityReportRecord{TrackingID: "sec_rotation", Severity: "high", Component: "API", Status: "received", BodyEnc: ciphertext, BodyAlg: "pgp", ContactEnc: []byte{1}, TokenHash: "test", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rotated, err := manager.Rotate(ctx, now)
	if err != nil {
		t.Fatalf("rotate project key: %v", err)
	}
	if rotated.Fingerprint == fingerprint {
		t.Fatal("rotation retained the old fingerprint")
	}
	report, err := db.GetSecurityReport(ctx, "sec_rotation")
	if err != nil || report == nil {
		t.Fatalf("load rotated report: %#v, %v", report, err)
	}
	decrypted, err = manager.Decrypt(report.BodyEnc)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypt report after rotation %q: %v", decrypted, err)
	}
	for name, mode := range map[string]os.FileMode{"pgp.pub.asc": 0600, "pgp.priv.asc.enc": 0600} {
		info, err := os.Stat(filepath.Join(configDir, "security", name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("key file %s permissions = %v, %v", name, info, err)
		}
	}
}

func TestSecurityKeypairPublicValidationLifecycleAndDeletion(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := NewSecurityKeypairManager("", bytes.Repeat([]byte{1}, 32), "Project", "security@example.test", db); err == nil {
		t.Fatal("empty key directory was accepted")
	}
	manager, err := NewSecurityKeypairManager(t.TempDir(), bytes.Repeat([]byte{2}, 32), "Project", "security@example.test", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Generate(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Generate(ctx, time.Now().UTC()); err == nil {
		t.Fatal("duplicate key generation was accepted")
	}
	publicKey, metadata, err := manager.PublicKey(ctx)
	if err != nil || metadata == nil || len(publicKey) == 0 {
		t.Fatalf("public key load = %d bytes, %#v, %v", len(publicKey), metadata, err)
	}
	if fingerprint, err := PGPFingerprint(publicKey); err != nil || fingerprint != metadata.Fingerprint {
		t.Fatalf("public key fingerprint = %q, %v", fingerprint, err)
	}
	if err := ValidateResearcherPGPKey(publicKey); err != nil {
		t.Fatalf("valid public key rejected: %v", err)
	}
	if err := ValidateResearcherPGPKey([]byte("not a key")); err == nil {
		t.Fatal("invalid researcher key was accepted")
	}
	if _, err := EncryptToPublicKey(publicKey, []byte("acknowledgment")); err != nil {
		t.Fatalf("encrypt to researcher key: %v", err)
	}
	if _, err := PGPFingerprint([]byte("not a key")); err == nil {
		t.Fatal("invalid key fingerprint input was accepted")
	}
	if _, err := SafeHTTPSKeyURL("https://keys.example.test/vks/v1/by-fingerprint/ABC"); err != nil {
		t.Fatalf("valid key URL rejected: %v", err)
	}
	for _, value := range []string{"http://keys.example.test/key", "https://user@keys.example.test/key", "https://keys.example.test/key#fragment", "/relative/key"} {
		if _, err := SafeHTTPSKeyURL(value); err == nil {
			t.Errorf("unsafe key URL %q was accepted", value)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/.well-known/pgp-key.asc", nil)
	response := httptest.NewRecorder()
	manager.PGPKeyHandler(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "application/pgp-keys") || !bytes.Equal(response.Body.Bytes(), publicKey) {
		t.Fatalf("public key response = %d headers=%v", response.Code, response.Header())
	}
	head := httptest.NewRecorder()
	manager.PGPKeyHandler(head, httptest.NewRequest(http.MethodHead, "/.well-known/pgp-key.asc", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD public key response = %d body=%d", head.Code, head.Body.Len())
	}
	method := httptest.NewRecorder()
	manager.PGPKeyHandler(method, httptest.NewRequest(http.MethodPost, "/.well-known/pgp-key.asc", nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("unsupported public key method = %d allow=%q", method.Code, method.Header().Get("Allow"))
	}
	manager.SetPublishEnabled(false)
	private := httptest.NewRecorder()
	manager.PGPKeyHandler(private, request)
	if private.Code != http.StatusNotFound {
		t.Fatalf("disabled public key endpoint status = %d", private.Code)
	}
	manager.SetPublishEnabled(true)
	rotatedAt := time.Now().UTC()
	if _, err := manager.Rotate(ctx, rotatedAt); err != nil {
		t.Fatalf("rotate before cleanup: %v", err)
	}
	if err := manager.CleanupOldPrivateKey(rotatedAt.Add(31 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(ctx, "wrong"); err == nil {
		t.Fatal("key deletion without confirmation phrase succeeded")
	}
	if err := manager.Delete(ctx, "DELETE SECURITY KEYPAIR"); err != nil {
		t.Fatalf("delete keypair: %v", err)
	}
	if _, _, err := manager.PublicKey(ctx); err != nil {
		t.Fatalf("revoked key metadata lookup returned error: %v", err)
	}
}
