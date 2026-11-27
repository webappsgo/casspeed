//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tor

import (
	"os/exec"
	"syscall"
	"time"
)

func terminateTorProcess(cmd *exec.Cmd, done <-chan struct{}) error {
	err := cmd.Process.Signal(syscall.SIGTERM)
	if done == nil {
		return err
	}
	select {
	case <-done:
		return err
	case <-time.After(10 * time.Second):
	}
	if killErr := cmd.Process.Kill(); killErr != nil && err == nil {
		err = killErr
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return err
}
