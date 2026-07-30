package email

import (
	"testing"
)

// ---- NewService tests ----------------------------------------------------

func TestNewService_StoresConfig(t *testing.T) {
	cfg := &Config{
		Enabled:  false,
		Host:     "smtp.example.com",
		Port:     587,
		Username: "user@example.com",
		From:     "noreply@example.com",
	}
	svc := NewService(cfg)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.config != cfg {
		t.Error("config not stored correctly")
	}
}

// ---- SendPasswordReset when disabled ------------------------------------

func TestSendPasswordReset_WhenDisabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	svc := NewService(cfg)

	err := svc.SendPasswordReset("user@example.com", "tok123", "https://example.com")
	if err == nil {
		t.Error("expected error when email is disabled")
	}
}

// ---- SendEmailVerification when disabled --------------------------------

func TestSendEmailVerification_WhenDisabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	svc := NewService(cfg)

	err := svc.SendEmailVerification("user@example.com", "tok456", "https://example.com")
	if err == nil {
		t.Error("expected error when email is disabled")
	}
}
