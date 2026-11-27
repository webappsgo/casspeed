//go:build !linux

package metrics

// CollectSystemMetrics is unavailable outside Linux; runtime metrics remain
// available through the Go runtime collector.
func CollectSystemMetrics(string) {}
