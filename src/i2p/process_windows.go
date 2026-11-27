//go:build windows

package i2p

import (
	"os"
	"os/exec"
	"time"
)

func setParentDeathSignal(*exec.Cmd) {}

func terminationSignal() os.Signal { return os.Interrupt }

func stopProcess(command *exec.Cmd, done <-chan struct{}) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
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

func isOwnedI2PD(int, string) bool { return false }

func processAlive(int) bool { return false }
