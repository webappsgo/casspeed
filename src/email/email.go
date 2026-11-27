package email

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	TLS      string
}

type Service struct {
	config *Config
}

// Available reports whether SMTP is configured for email delivery.
func (s *Service) Available() bool {
	return s != nil && s.config != nil && s.config.Enabled && s.config.Host != ""
}

func NewService(cfg *Config) *Service {
	return &Service{config: cfg}
}

func (s *Service) SendPasswordReset(to, token, appURL string) error {
	if !s.config.Enabled {
		return fmt.Errorf("email not configured")
	}

	subject := "Password Reset Request"
	body := fmt.Sprintf(`
Password Reset Request

Click the link below to reset your password:
%s/auth/password/reset?token=%s

This link expires in 1 hour.

If you did not request this, please ignore this email.
`, appURL, token)

	return s.send(to, subject, body)
}

func (s *Service) SendEmailVerification(to, token, appURL string) error {
	if !s.config.Enabled {
		return fmt.Errorf("email not configured")
	}

	subject := "Email Verification"
	body := fmt.Sprintf(`
Email Verification

Click the link below to verify your email:
%s/auth/verify?token=%s

If you did not create an account, please ignore this email.
`, appURL, token)

	return s.send(to, subject, body)
}

func (s *Service) send(to, subject, body string) error {
	return s.SendMessage(to, "", subject, body)
}

// SendMessage sends one message using the configured SMTP transport.
func (s *Service) SendMessage(to, replyTo, subject, body string) error {
	if s.config == nil || !s.config.Enabled || s.config.Host == "" {
		return fmt.Errorf("email not configured")
	}
	if strings.ContainsAny(subject, "\r\n") || strings.ContainsAny(replyTo, "\r\n") || strings.ContainsAny(s.config.FromName, "\r\n") {
		return fmt.Errorf("invalid email header")
	}
	toAddress, err := mail.ParseAddress(to)
	if err != nil || toAddress.Address != to {
		return fmt.Errorf("invalid recipient address")
	}
	from := s.config.From
	if from == "" {
		from = s.config.Username
	}
	fromAddress, err := mail.ParseAddress(from)
	if err != nil || fromAddress.Address != from {
		return fmt.Errorf("invalid sender address")
	}
	if replyTo != "" {
		parsed, parseErr := mail.ParseAddress(replyTo)
		if parseErr != nil || parsed.Address != replyTo {
			return fmt.Errorf("invalid reply address")
		}
	}
	if s.config.Username != "" && s.config.TLS == "none" {
		return fmt.Errorf("SMTP authentication requires TLS")
	}

	fromHeader := from
	if s.config.FromName != "" {
		fromHeader = mime.QEncoding.Encode("utf-8", s.config.FromName) + " <" + from + ">"
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\n", fromHeader, to)
	if replyTo != "" {
		message += "Reply-To: " + replyTo + "\r\n"
	}
	message += fmt.Sprintf("Subject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", subject, body)

	port := s.config.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(s.config.Host, strconv.Itoa(port))
	tlsMode := s.config.TLS
	if tlsMode == "" || (tlsMode != "auto" && tlsMode != "starttls" && tlsMode != "tls" && tlsMode != "none") {
		tlsMode = "auto"
	}
	implicitTLS := tlsMode == "tls" || (tlsMode == "auto" && port == 465)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if implicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.config.Host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if !implicitTLS && tlsMode != "none" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.config.Host}); err != nil {
				return err
			}
		} else if tlsMode == "starttls" || s.config.Username != "" {
			return fmt.Errorf("SMTP server does not offer STARTTLS")
		}
	}
	if s.config.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("SMTP server does not offer authentication")
		}
		if err := client.Auth(smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(fromAddress.Address); err != nil {
		return err
	}
	if err := client.Rcpt(toAddress.Address); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
