//go:build linux

package i2p

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func setParentDeathSignal(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

func terminationSignal() os.Signal { return syscall.SIGTERM }

func stopProcess(command *exec.Cmd, done <-chan struct{}) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func isOwnedI2PD(pid int, dataDir string) bool {
	contents, err := os.ReadFile(filepath.Join("/proc", itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	arguments := strings.Split(string(contents), "\x00")
	if len(arguments) == 0 || arguments[0] == "" {
		return false
	}
	for index := 1; index+1 < len(arguments); index++ {
		if arguments[index] == "--datadir" && filepath.Clean(arguments[index+1]) == filepath.Clean(dataDir) {
			return true
		}
	}
	return false
}

func processAlive(pid int) bool {
	_, err := os.Stat(filepath.Join("/proc", itoa(pid)))
	return err == nil
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
