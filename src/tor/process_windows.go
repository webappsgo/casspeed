//go:build windows

package tor

import (
	"os/exec"
	"time"
)

func terminateTorProcess(cmd *exec.Cmd, done <-chan struct{}) error {
	err := cmd.Process.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return err
}
