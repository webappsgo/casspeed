package auth

import (
	"strings"
	"testing"
	"time"
)

// TestHashPassword covers the basic hash→verify round-trip and format contract.
func TestHashPassword(t *testing.T) {
	t.Run("valid password produces salt$hash format", func(t *testing.T) {
		h, err := HashPassword("correcthorsebatterystaple")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		parts := strings.SplitN(h, "$", 2)
		if len(parts) != 2 {
			t.Fatalf("expected 'salt$hash' format, got %q", h)
		}
		// salt = 16 bytes hex = 32 chars; hash = 32 bytes hex = 64 chars
		if len(parts[0]) != 32 {
			t.Errorf("salt hex length = %d, want 32", len(parts[0]))
		}
		if len(parts[1]) != 64 {
			t.Errorf("hash hex length = %d, want 64", len(parts[1]))
		}
	})

	t.Run("same password produces different hashes each call", func(t *testing.T) {
		h1, err1 := HashPassword("password")
		h2, err2 := HashPassword("password")
		if err1 != nil || err2 != nil {
			t.Fatalf("hash errors: %v %v", err1, err2)
		}
		if h1 == h2 {
			t.Error("two hashes of the same password must differ (random salt)")
		}
	})

	t.Run("empty password is accepted", func(t *testing.T) {
		h, err := HashPassword("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(h, "$") {
			t.Errorf("hash %q missing separator", h)
		}
	})
}

// TestVerifyPassword covers correct, wrong-password, empty, and malformed inputs.
func TestVerifyPassword(t *testing.T) {
	hash, err := HashPassword("s3cr3t!")
	if err != nil {
		t.Fatalf("setup hash error: %v", err)
	}

	t.Run("correct password verifies true", func(t *testing.T) {
		if !VerifyPassword("s3cr3t!", hash) {
			t.Error("correct password should verify")
		}
	})

	t.Run("wrong password verifies false", func(t *testing.T) {
		if VerifyPassword("wrong", hash) {
			t.Error("wrong password should not verify")
		}
	})

	t.Run("empty password against real hash verifies false", func(t *testing.T) {
		if VerifyPassword("", hash) {
			t.Error("empty password should not verify against a real hash")
		}
	})

	t.Run("malformed hash returns false", func(t *testing.T) {
		cases := []string{
			"",
			"notahash",
			"$",
			"noseparator",
			"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		}
		for _, bad := range cases {
			if VerifyPassword("anything", bad) {
				t.Errorf("expected false for malformed hash %q", bad)
			}
		}
	})

	t.Run("empty password hashes and verifies round-trip", func(t *testing.T) {
		h, _ := HashPassword("")
		if !VerifyPassword("", h) {
			t.Error("empty password should verify against its own hash")
		}
	})
}

// TestGenerateSessionID covers length, hex format, and uniqueness.
func TestGenerateSessionID(t *testing.T) {
	t.Run("length is 64 hex chars (32 bytes)", func(t *testing.T) {
		id := GenerateSessionID()
		if len(id) != 64 {
			t.Errorf("session ID length = %d, want 64", len(id))
		}
	})

	t.Run("contains only hex characters", func(t *testing.T) {
		id := GenerateSessionID()
		for _, c := range id {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("non-hex character %q in session ID %q", c, id)
			}
		}
	})

	t.Run("two calls produce different IDs", func(t *testing.T) {
		if GenerateSessionID() == GenerateSessionID() {
			t.Error("consecutive session IDs should differ")
		}
	})
}

// TestGeneratePasswordResetToken covers the token structure and expiry window.
func TestGeneratePasswordResetToken(t *testing.T) {
	const userID = "user-42"

	t.Run("returns non-nil token", func(t *testing.T) {
		tok := GeneratePasswordResetToken(userID)
		if tok == nil {
			t.Fatal("expected non-nil token")
		}
	})

	t.Run("token carries correct userID", func(t *testing.T) {
		tok := GeneratePasswordResetToken(userID)
		if tok.UserID != userID {
			t.Errorf("UserID = %q, want %q", tok.UserID, userID)
		}
	})

	t.Run("token is 64 hex chars (32 bytes)", func(t *testing.T) {
		tok := GeneratePasswordResetToken(userID)
		if len(tok.Token) != 64 {
			t.Errorf("token length = %d, want 64", len(tok.Token))
		}
	})

	t.Run("expires approximately one hour from now", func(t *testing.T) {
		before := time.Now()
		tok := GeneratePasswordResetToken(userID)
		after := time.Now()

		minExpiry := before.Add(59 * time.Minute)
		maxExpiry := after.Add(61 * time.Minute)

		if tok.ExpiresAt.Before(minExpiry) || tok.ExpiresAt.After(maxExpiry) {
			t.Errorf("ExpiresAt %v not within expected 1-hour window", tok.ExpiresAt)
		}
	})

	t.Run("two calls produce different tokens", func(t *testing.T) {
		t1 := GeneratePasswordResetToken(userID)
		t2 := GeneratePasswordResetToken(userID)
		if t1.Token == t2.Token {
			t.Error("consecutive tokens should differ")
		}
	})
}

// TestNewSession covers session creation and expiry logic.
func TestNewSession(t *testing.T) {
	t.Run("session fields populated", func(t *testing.T) {
		before := time.Now()
		s := NewSession("uid-1", "127.0.0.1", "TestAgent/1.0")
		after := time.Now()

		if s.UserID != "uid-1" {
			t.Errorf("UserID = %q", s.UserID)
		}
		if s.IPAddress != "127.0.0.1" {
			t.Errorf("IPAddress = %q", s.IPAddress)
		}
		if s.UserAgent != "TestAgent/1.0" {
			t.Errorf("UserAgent = %q", s.UserAgent)
		}
		if len(s.ID) != 64 {
			t.Errorf("ID length = %d, want 64", len(s.ID))
		}
		if s.CreatedAt.Before(before) || s.CreatedAt.After(after) {
			t.Errorf("CreatedAt out of range")
		}
	})

	t.Run("fresh session is not expired", func(t *testing.T) {
		s := NewSession("u", "ip", "ua")
		if s.IsExpired() {
			t.Error("fresh session should not be expired")
		}
	})

	t.Run("session with past expiry is expired", func(t *testing.T) {
		s := NewSession("u", "ip", "ua")
		s.ExpiresAt = time.Now().Add(-1 * time.Second)
		if !s.IsExpired() {
			t.Error("session with past expiry should be expired")
		}
	})
}

// TestValidateUsername covers boundary lengths.
func TestValidateUsername(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"too short 2 chars", "ab", true},
		{"minimum 3 chars", "abc", false},
		{"normal", "alice", false},
		{"max 30 chars", strings.Repeat("a", 30), false},
		{"too long 31 chars", strings.Repeat("a", 31), true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUsername(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateUsername(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestValidateEmail covers the @ presence requirement.
func TestValidateEmail(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"missing @", "userexample.com", true},
		{"empty", "", true},
		// "@" alone: the contains() helper requires len(s) >= len(substr) AND s >= 3,
		// but "@" is only 1 char, so the length-3 guard fires first → error.
		{"only @", "@", true},
		{"short no @", "ab", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateEmail(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestValidatePassword covers the 8-character minimum.
func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"7 chars", "passwor", true},
		{"exactly 8", "password", false},
		{"long", strings.Repeat("a", 100), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePassword(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}
