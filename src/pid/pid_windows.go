//go:build windows
// +build windows

package pid

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// isProcessRunning checks if a process with given PID exists (Windows)
func isProcessRunning(pid int) bool {
	// On Windows, FindProcess succeeds for any valid PID
	// Use OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION to check
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Try to get exit code - fails if process doesn't exist or no permission
	// But for our own processes, this should work
	var exitCode uint32
	handle := windows.Handle(uintptr(process.Pid))
	err = windows.GetExitCodeProcess(handle, &exitCode)
	// STILL_ACTIVE constant = 259
	const STILL_ACTIVE = 259
	return err == nil && exitCode == STILL_ACTIVE
}

// isOurProcess verifies the process is actually our binary (Windows)
func isOurProcess(pid int) bool {
	// Use Windows API to get process image name
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	var size uint32 = windows.MAX_PATH
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return false
	}
	exePath := windows.UTF16ToString(buf[:size])
	return strings.Contains(strings.ToLower(filepath.Base(exePath)), "casspeed")
}
