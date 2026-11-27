//go:build linux

package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var cpuSample struct {
	sync.Mutex
	total uint64
	idle  uint64
}

// CollectSystemMetrics reads Linux host CPU, memory, and data filesystem usage.
func CollectSystemMetrics(dataPath string) {
	var cpuPercent, memoryPercent, memoryUsed, memoryTotal, diskPercent, diskUsed, diskTotal float64
	if contents, err := os.ReadFile("/proc/stat"); err == nil {
		fields := strings.Fields(strings.SplitN(string(contents), "\n", 2)[0])
		if len(fields) >= 5 && fields[0] == "cpu" {
			var total, idle uint64
			for index, field := range fields[1:] {
				value, parseErr := strconv.ParseUint(field, 10, 64)
				if parseErr != nil {
					break
				}
				total += value
				if index == 3 || index == 4 {
					idle += value
				}
			}
			cpuSample.Lock()
			if total > cpuSample.total && idle >= cpuSample.idle {
				deltaTotal, deltaIdle := total-cpuSample.total, idle-cpuSample.idle
				if deltaTotal > 0 {
					cpuPercent = float64(deltaTotal-deltaIdle) * 100 / float64(deltaTotal)
				}
			}
			cpuSample.total, cpuSample.idle = total, idle
			cpuSample.Unlock()
		}
	}
	if file, err := os.Open("/proc/meminfo"); err == nil {
		values := make(map[string]uint64)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr == nil {
				values[strings.TrimSuffix(fields[0], ":")] = value * 1024
			}
		}
		_ = file.Close()
		memoryTotal = float64(values["MemTotal"])
		memoryUsed = memoryTotal - float64(values["MemAvailable"])
		if memoryTotal > 0 {
			memoryPercent = memoryUsed * 100 / memoryTotal
		}
	}
	if dataPath == "" {
		dataPath = "."
	}
	if absolute, err := filepath.Abs(dataPath); err == nil {
		dataPath = absolute
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dataPath, &fs); err == nil && fs.Blocks > 0 {
		diskTotal = float64(fs.Blocks) * float64(fs.Bsize)
		diskUsed = float64(fs.Blocks-fs.Bfree) * float64(fs.Bsize)
		diskPercent = diskUsed * 100 / diskTotal
	}
	SetSystemMetrics(cpuPercent, memoryPercent, memoryUsed, memoryTotal, diskPercent, diskUsed, diskTotal, dataPath)
}
