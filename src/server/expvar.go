package server

import (
	"expvar"
	"runtime"
	"time"
)

var (
	expRequestCount    = expvar.NewInt("requests_total")
	expRequestDuration = expvar.NewFloat("requests_duration_seconds")
	expErrorCount      = expvar.NewInt("errors_total")
	expStartTime       = time.Now()
)

func init() {
	// Publish uptime
	expvar.Publish("uptime_seconds", expvar.Func(func() any {
		return time.Since(expStartTime).Seconds()
	}))

	// Publish goroutine count
	expvar.Publish("goroutines", expvar.Func(func() any {
		return runtime.NumGoroutine()
	}))

	// Publish memory stats
	expvar.Publish("memory", expvar.Func(func() any {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return map[string]uint64{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"heap_alloc":  m.HeapAlloc,
			"heap_sys":    m.HeapSys,
		}
	}))
}

// recordRequest records a completed request for expvar metrics.
func recordRequest(duration time.Duration) {
	expRequestCount.Add(1)
	expRequestDuration.Add(duration.Seconds())
}

// recordError records an error occurrence for expvar metrics.
func recordError() {
	expErrorCount.Add(1)
}
