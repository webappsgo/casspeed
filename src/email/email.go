package email

import (
"crypto/tls"
"fmt"
"net/smtp"
)

type Config struct {
Enabled  bool
Host     string
Port     int
Username string
Password string
From     string
}

type Service struct {
config *Config
}

func NewService(cfg *Config) *Service {
return &Service{config: cfg}
}

func (s *Service) SendPasswordReset(to, token, appURL string) error {
if !s.config.Enabled{
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
if !s.config.Enabled{
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
from := s.config.From
if from == "" {
from = s.config.Username
}

msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
from, to, subject, body)

addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

// Use TLS
tlsconfig := &tls.Config{
InsecureSkipVerify: false,
ServerName:         s.config.Host,
}

conn, err := tls.Dial("tcp", addr, tlsconfig)
if err != nil {
return err
}
defer conn.Close()

c, err := smtp.NewClient(conn, s.config.Host)
if err != nil {
return err
}
defer c.Close()

if err = c.Auth(auth); err != nil {
return err
}

if err = c.Mail(from); err != nil {
return err
}

if err = c.Rcpt(to); err != nil {
return err
}

w, err := c.Data()
if err != nil {
return err
}

_, err = w.Write([]byte(msg))
if err != nil {
return err
}

err = w.Close()
if err != nil {
return err
}

return c.Quit()
}
