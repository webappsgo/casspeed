package server

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestEncryptResearcherAcknowledgmentArmorsCiphertext(t *testing.T) {
	entity, err := openpgp.NewEntity("Researcher", "", "researcher@example.invalid", nil)
	if err != nil {
		t.Fatalf("create researcher key: %v", err)
	}
	var publicKey bytes.Buffer
	writer, err := armor.Encode(&publicKey, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor researcher key: %v", err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatalf("serialize researcher key: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("finish researcher key: %v", err)
	}

	message, err := EncryptResearcherAcknowledgment(context.Background(), publicKey.String(), []byte("tracking id only"))
	if err != nil {
		t.Fatalf("encrypt acknowledgment: %v", err)
	}
	if !strings.HasPrefix(string(message), "-----BEGIN PGP MESSAGE-----") || strings.Contains(string(message), "tracking id only") {
		t.Fatal("acknowledgment was not safely armored and encrypted")
	}
}

func TestFetchResearcherPublicKeyRejectsPrivateAddress(t *testing.T) {
	if _, err := fetchResearcherPublicKey(context.Background(), "https://127.0.0.1/key.asc"); err == nil {
		t.Fatal("private key host was accepted")
	}
}

func TestPublicResearcherKeyIPRejectsNonRoutableRanges(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "100.64.0.1", "192.0.2.1", "2001:db8::1", "::1"} {
		address := netip.MustParseAddr(raw)
		if publicResearcherKeyIP(address) {
			t.Errorf("publicResearcherKeyIP(%s) = true, want false", raw)
		}
	}
	if !publicResearcherKeyIP(netip.MustParseAddr("8.8.8.8")) {
		t.Error("publicResearcherKeyIP(8.8.8.8) = false, want true")
	}
}
