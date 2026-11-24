package server

import (
	"log/slog"
	"net/http"
	"time"
)

// debugLog logs detailed request information (--debug/DEBUG=true only).
func (s *Server) debugLog(r *http.Request, status int, duration time.Duration, size int) {
	if !s.Mode.IsDebug() {
		return
	}

	slog.Debug("request",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"status", status,
		"duration_ms", duration.Milliseconds(),
		"size", size,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"referer", r.Referer(),
		"request_id", r.Header.Get("X-Request-ID"),
	)
}
