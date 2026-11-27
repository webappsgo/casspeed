package tor

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestOnionV3AddressDerivationAndValidation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address := onionV3Address(publicKey)
	if !validOnionAddress(address) {
		t.Fatalf("derived v3 onion address %q did not validate", address)
	}
	first := byte('a')
	if address[0] == first {
		first = 'b'
	}
	mutated := string(first) + address[1:]
	if validOnionAddress(mutated) {
		t.Fatalf("mutated v3 onion address %q unexpectedly validated", mutated)
	}
}

func TestValidateVanityPrefix(t *testing.T) {
	for _, prefix := range []string{"a", "myapp", "test27"} {
		if err := ValidateVanityPrefix(prefix); err != nil {
			t.Errorf("ValidateVanityPrefix(%q) = %v", prefix, err)
		}
	}
	for _, prefix := range []string{"", "ABCDEFG", "UPPER", "bad-prefix", "1", "1234567"} {
		if err := ValidateVanityPrefix(prefix); err == nil {
			t.Errorf("ValidateVanityPrefix(%q) unexpectedly succeeded", prefix)
		}
	}
}

func TestVanityCandidateStorageAndImport(t *testing.T) {
	dataDir := t.TempDir()
	manager := NewVanityManager(dataDir)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address := onionV3Address(publicKey)
	root := filepath.Join(dataDir, "source")
	if err := writeVanityCandidate(root, address, privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	candidateDir := filepath.Join(root, address)
	if _, err := readVanityCandidate(candidateDir, address); err != nil {
		t.Fatalf("read generated candidate: %v", err)
	}
	for _, name := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"} {
		info, err := os.Stat(filepath.Join(candidateDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s permissions = %04o, want 0600", name, info.Mode().Perm())
		}
	}
	imported, err := manager.ImportCandidate(candidateDir)
	if err != nil {
		t.Fatal(err)
	}
	if imported != address {
		t.Fatalf("imported address = %q, want %q", imported, address)
	}
	if candidates := manager.Candidates(); len(candidates) != 1 || candidates[0] != address {
		t.Fatalf("candidate list = %#v, want [%q]", candidates, address)
	}
}

func TestImportKeyFilesDerivesMissingPublicKeyAndHostname(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := expandedTorPrivateKey(privateKey[:ed25519.SeedSize])
	if err != nil {
		t.Fatal(err)
	}
	secretFile := append([]byte(vanitySecretHeader), secret...)
	manager := NewVanityManager(t.TempDir())
	address, err := manager.ImportKeyFiles(secretFile, nil, nil)
	if err != nil {
		t.Fatalf("import secret key only: %v", err)
	}
	if address != onionV3Address(publicKey) {
		t.Fatalf("imported address = %q, want %q", address, onionV3Address(publicKey))
	}
	if _, err := readVanityCandidate(filepath.Join(manager.root, address), address); err != nil {
		t.Fatalf("derived candidate is invalid: %v", err)
	}
}

func TestImportKeyFilesRejectsMismatchedOptionalIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := expandedTorPrivateKey(privateKey[:ed25519.SeedSize])
	if err != nil {
		t.Fatal(err)
	}
	secretFile := append([]byte(vanitySecretHeader), secret...)
	differentPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicFile := append([]byte(vanityPublicHeader), differentPublic...)
	manager := NewVanityManager(t.TempDir())
	if _, err := manager.ImportKeyFiles(secretFile, publicFile, []byte(onionV3Address(publicKey))); err == nil {
		t.Fatal("mismatched public key was accepted")
	}
	if _, err := manager.ImportKeyFiles(secretFile, nil, []byte("invalid.onion")); err == nil {
		t.Fatal("mismatched hostname was accepted")
	}
}
