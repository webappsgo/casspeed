package server

import (
	"github.com/casapps/casspeed/src/auth"
)

func (s *Server) validateUserPassword(password string) error {
	if s == nil || s.Config == nil {
		return auth.ValidatePassword(password)
	}
	policy := s.Config.Server.Users.Auth
	return auth.ValidatePasswordPolicy(password, policy.PasswordMinLength, policy.PasswordRequireUppercase, policy.PasswordRequireNumber, policy.PasswordRequireSpecial)
}
