package auth

import (
	"regexp"
	"testing"
	"time"
)

func TestVerifyTOTPMatchesRFC6238SHA1Vector(t *testing.T) {
	if !VerifyTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "287082", time.Unix(59, 0)) {
		t.Fatal("RFC 6238 code was rejected")
	}
	if VerifyTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "287083", time.Unix(59, 0)) {
		t.Fatal("incorrect TOTP code was accepted")
	}
}

func TestNewRecoveryCodesHaveRequiredFormatAndCount(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("generated %d recovery keys, want 10", len(codes))
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}$`)
	seen := make(map[string]bool)
	for _, code := range codes {
		if !pattern.MatchString(code) || seen[code] {
			t.Fatalf("invalid or duplicate recovery key %q", code)
		}
		seen[code] = true
	}
}
