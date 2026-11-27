//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if err := os.Rename(temporaryPath, target); err != nil {
		return fmt.Errorf("atomically replace CLI binary: %w", err)
	}
	return nil
}
