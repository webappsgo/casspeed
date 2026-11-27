package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// NewTOTPSecret returns a cryptographically random base32 secret for an authenticator.
func NewTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// VerifyTOTP validates a six-digit RFC 6238 code within one 30-second clock window.
func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	step := now.Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step+offset))
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(counter[:])
		sum := mac.Sum(nil)
		index := sum[len(sum)-1] & 0x0f
		value := (binary.BigEndian.Uint32(sum[index:index+4]) & 0x7fffffff) % 1000000
		candidate := fmt.Sprintf("%06d", value)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// NewRecoveryCodes creates ten one-time recovery codes in the documented format.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := range codes {
		random := make([]byte, 6)
		if _, err := rand.Read(random); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		encoded := hex.EncodeToString(random)
		codes[i] = encoded[:8] + "-" + encoded[8:]
	}
	return codes, nil
}
