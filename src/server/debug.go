package server

import (
	"database/sql"
	"expvar"
	"net/http"
	"net/http/pprof"
	"runtime"

	"github.com/go-chi/chi/v5"
)

// dbStatter is a narrow interface for stores that expose sql.DBStats.
type dbStatter interface {
	DBStats() sql.DBStats
}

// registerDebugRoutes registers debug endpoints (--debug/DEBUG=true only).
func (s *Server) registerDebugRoutes(r chi.Router) {
	if !s.Mode.IsDebug() {
		return
	}

	r.Route("/debug", func(r chi.Router) {
		// pprof endpoints
		r.HandleFunc("/pprof/", pprof.Index)
		r.HandleFunc("/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/pprof/profile", pprof.Profile)
		r.HandleFunc("/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/pprof/trace", pprof.Trace)
		r.Handle("/pprof/heap", pprof.Handler("heap"))
		r.Handle("/pprof/goroutine", pprof.Handler("goroutine"))
		r.Handle("/pprof/allocs", pprof.Handler("allocs"))
		r.Handle("/pprof/block", pprof.Handler("block"))
		r.Handle("/pprof/mutex", pprof.Handler("mutex"))
		r.Handle("/pprof/threadcreate", pprof.Handler("threadcreate"))

		// expvar
		r.Handle("/vars", expvar.Handler())

		// Custom debug endpoints
		r.Get("/config", s.handleDebugConfig)
		r.Get("/routes", s.handleDebugRoutes)
		r.Get("/cache", s.handleDebugCache)
		r.Get("/db", s.handleDebugDB)
		r.Get("/scheduler", s.handleDebugScheduler)
		r.Get("/memory", s.handleDebugMemory)
		r.Get("/goroutines", s.handleDebugGoroutines)
	})
}

// handleDebugConfig returns sanitized configuration.
func (s *Server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"mode":  s.Mode.String(),
		"debug": s.Mode.IsDebug(),
	})
}

// handleDebugRoutes returns all registered routes.
func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) {
	routes := []map[string]string{}

	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, map[string]string{
			"method": method,
			"route":  route,
		})
		return nil
	}

	if err := chi.Walk(s.Router, walkFunc); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to walk routes")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"count":  len(routes),
		"routes": routes,
	})
}

// handleDebugMemory returns memory statistics.
func (s *Server) handleDebugMemory(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	respondJSON(w, http.StatusOK, map[string]any{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         m.NumGC,
		"heap_objects":   m.HeapObjects,
		"goroutines":     runtime.NumGoroutine(),
	})
}

// handleDebugGoroutines returns goroutine count and stack traces.
func (s *Server) handleDebugGoroutines(w http.ResponseWriter, r *http.Request) {
	// 1 MB buffer for stack traces
	buf := make([]byte, 1024*1024)
	// true = include all goroutines
	n := runtime.Stack(buf, true)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(buf[:n])
}

// handleDebugCache returns cache statistics (placeholder until PART 9 cache is wired).
func (s *Server) handleDebugCache(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"note": "cache not yet initialized",
	})
}

// handleDebugDB returns database statistics.
func (s *Server) handleDebugDB(w http.ResponseWriter, r *http.Request) {
	if st, ok := s.Store.(dbStatter); ok {
		stats := st.DBStats()
		respondJSON(w, http.StatusOK, map[string]any{
			"open_connections":    stats.OpenConnections,
			"in_use":              stats.InUse,
			"idle":                stats.Idle,
			"wait_count":          stats.WaitCount,
			"wait_duration_ms":    stats.WaitDuration.Milliseconds(),
			"max_idle_closed":     stats.MaxIdleClosed,
			"max_lifetime_closed": stats.MaxLifetimeClosed,
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"note": "store does not expose db stats",
	})
}

// handleDebugScheduler returns scheduler task status (placeholder until PART 12 scheduler is wired).
func (s *Server) handleDebugScheduler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"note": "scheduler not yet initialized",
	})
}
