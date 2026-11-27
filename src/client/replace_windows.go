//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func replaceCLIExecutablePlatform(source, target string) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat current CLI binary: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".casspeed-cli-update-*")
	if err != nil {
		return fmt.Errorf("create replacement beside current CLI binary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	sourceFile, err := os.Open(source)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("open staged CLI binary: %w", err)
	}
	_, copyErr := io.Copy(temporary, sourceFile)
	closeSourceErr := sourceFile.Close()
	if copyErr != nil {
		_ = temporary.Close()
		return fmt.Errorf("copy staged CLI binary: %w", copyErr)
	}
	if closeSourceErr != nil {
		_ = temporary.Close()
		return fmt.Errorf("close staged CLI binary: %w", closeSourceErr)
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set replacement permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync replacement binary: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close replacement binary: %w", err)
	}

	oldPath := target + ".old"
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous CLI backup %s: %w", oldPath, err)
	}
	if err := os.Rename(target, oldPath); err != nil {
		return fmt.Errorf("rename running CLI binary to its backup: %w", err)
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		restoreErr := os.Rename(oldPath, target)
		if restoreErr != nil {
			return fmt.Errorf("install replacement CLI binary: %w; restore original binary: %v", err, restoreErr)
		}
		return fmt.Errorf("install replacement CLI binary: %w", err)
	}

	oldPathUTF16, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return fmt.Errorf("encode old CLI binary path for cleanup: %w", err)
	}
	if err := windows.MoveFileEx(oldPathUTF16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		return fmt.Errorf("schedule old CLI binary cleanup: %w", err)
	}
	return nil
}
