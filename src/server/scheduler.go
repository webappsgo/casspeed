package server

import (
	"context"
	"fmt"
	"time"

	"github.com/casapps/casspeed/src/scheduler"
)

func (s *Server) initializeScheduler(timezone string) error {
	if timezone == "" {
		timezone = "America/New_York"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		if s.Logger != nil && s.Logger.Error != nil {
			s.Logger.Error.Printf("invalid server.scheduler.timezone %q; using America/New_York", timezone)
		}
		timezone = "America/New_York"
	}
	instance, err := scheduler.New(timezone)
	if err != nil {
		return err
	}
	s.Scheduler = instance
	tasks := []*scheduler.Task{
		{ID: "session_cleanup", Name: "Session and anonymous result cleanup", Schedule: s.taskSchedule("session_cleanup", "*/15 * * * *"), Enabled: true, Handler: s.cleanupSessions},
		{ID: "token_cleanup", Name: "Token and CAPTCHA cleanup", Schedule: s.taskSchedule("token_cleanup", "*/15 * * * *"), Enabled: true, Handler: s.cleanupTokens},
		{ID: "security_cleanup", Name: "Security report and key cleanup", Schedule: s.taskSchedule("security_cleanup", "30 3 * * *"), Enabled: true, Handler: s.cleanupSecurityData},
	}
	for _, task := range tasks {
		if err := instance.AddTask(task); err != nil {
			instance.Stop()
			return fmt.Errorf("register %s task: %w", task.ID, err)
		}
	}
	if s.Logger != nil && s.Logger.Server != nil {
		s.Logger.Server.Printf("scheduler registered tasks: session_cleanup, token_cleanup, security_cleanup")
	}
	return nil
}

func (s *Server) taskSchedule(name, fallback string) string {
	if task, exists := s.Config.Server.Scheduler.Tasks[name]; exists && task.Schedule != "" {
		return task.Schedule
	}
	return fallback
}

func (s *Server) cleanupSessions(ctx context.Context) error {
	if err := s.Store.DeleteExpiredSessions(ctx); err != nil {
		return fmt.Errorf("remove expired user sessions: %w", err)
	}
	if err := s.Store.DeleteExpiredAdminSessions(ctx); err != nil {
		return fmt.Errorf("remove expired admin sessions: %w", err)
	}
	if s.Config != nil && s.Config.Test.ResultsRetention > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.Config.Test.ResultsRetention)
		if err := s.Store.DeleteAnonymousSpeedTestsBefore(ctx, cutoff); err != nil {
			return fmt.Errorf("remove expired anonymous speed tests: %w", err)
		}
	}
	return nil
}

func (s *Server) cleanupTokens(ctx context.Context) error {
	if err := s.Store.DeleteExpiredAPITokens(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("remove expired API tokens: %w", err)
	}
	if err := s.Store.DeleteExpiredPasswordResetTokens(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("remove expired password reset tokens: %w", err)
	}
	if err := s.Store.DeleteExpiredCaptchaChallenges(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("remove expired CAPTCHA challenges: %w", err)
	}
	return nil
}

func (s *Server) cleanupSecurityData(ctx context.Context) error {
	if _, err := s.SecurityReports.Cleanup(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("remove expired security reports: %w", err)
	}
	if err := s.SecurityKeypair.CleanupOldPrivateKey(time.Now().UTC()); err != nil {
		return fmt.Errorf("remove retired security key: %w", err)
	}
	return nil
}
