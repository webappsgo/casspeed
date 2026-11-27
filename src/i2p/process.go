package i2p

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func startI2PD(ctx context.Context, cfg Config, binary string) (string, *exec.Cmd, chan struct{}, error) {
	configDir := filepath.Join(cfg.ConfigDir, "i2p")
	dataDir := filepath.Join(cfg.DataDir, "i2p")
	confPath := filepath.Join(configDir, "i2pd.conf")
	tunnelConfig := filepath.Join(configDir, "tunnels.conf")
	tunnelDir := filepath.Join(configDir, "tunnels.d")
	pidPath := filepath.Join(dataDir, "i2pd.pid")
	reapStaleI2PD(pidPath, dataDir)
	samPort, err := unusedPort()
	if err != nil {
		return "", nil, nil, err
	}
	if err := writePrivateFile(confPath, []byte(i2pdConfig(samPort, filepath.Join(cfg.LogDir, "i2pd.log")))); err != nil {
		return "", nil, nil, fmt.Errorf("write i2pd.conf: %w", err)
	}
	if err := writePrivateFile(tunnelConfig, nil); err != nil {
		return "", nil, nil, fmt.Errorf("write empty tunnels.conf: %w", err)
	}
	if err := os.MkdirAll(tunnelDir, 0700); err != nil {
		return "", nil, nil, fmt.Errorf("create empty tunnels directory: %w", err)
	}
	if err := os.Chmod(tunnelDir, 0700); err != nil {
		return "", nil, nil, fmt.Errorf("secure tunnels directory: %w", err)
	}
	entries, err := os.ReadDir(tunnelDir)
	if err != nil {
		return "", nil, nil, fmt.Errorf("read tunnels directory: %w", err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(tunnelDir, entry.Name())); err != nil {
			return "", nil, nil, fmt.Errorf("clear app-owned tunnels directory: %w", err)
		}
	}
	command := exec.Command(binary, "--conf", confPath, "--tunconf", tunnelConfig, "--tunnelsdir", tunnelDir, "--datadir", dataDir, "--pidfile", pidPath)
	setParentDeathSignal(command)
	if err := command.Start(); err != nil {
		return "", nil, nil, fmt.Errorf("start i2pd: %w", err)
	}
	processDone := make(chan struct{})
	go func() { _ = command.Wait(); close(processDone) }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(samPort))
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, _, probeErr := dialSAM(probeCtx, address)
		cancel()
		if probeErr == nil {
			_ = conn.Close()
			return address, command, processDone, nil
		}
		select {
		case <-processDone:
			return "", nil, nil, errors.New("i2pd exited before its SAM listener became ready; inspect i2pd.log")
		case <-ctx.Done():
			stopProcess(command, processDone)
			return "", nil, nil, ctx.Err()
		case <-deadline.C:
			stopProcess(command, processDone)
			return "", nil, nil, errors.New("i2pd SAM listener did not become ready within 60 seconds; inspect i2pd.log")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func i2pdConfig(samPort int, logPath string) string {
	logPath = strings.ReplaceAll(logPath, "\\", "\\\\")
	logPath = strings.ReplaceAll(logPath, "\n", "")
	logPath = strings.ReplaceAll(logPath, "\r", "")
	return fmt.Sprintf("daemon = false\nipv4 = true\nipv6 = false\nnotransit = true\nfloodfill = false\nlog = file\nlogfile = %s\nloglevel = warn\n\n[http]\nenabled = false\n[httpproxy]\nenabled = false\n[socksproxy]\nenabled = false\n[sam]\nenabled = true\naddress = 127.0.0.1\nport = %d\n[bob]\nenabled = false\n[i2cp]\nenabled = false\n[i2pcontrol]\nenabled = false\n[upnp]\nenabled = false\n", logPath, samPort)
}

func unusedPort() (int, error) {
	start, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return 0, fmt.Errorf("choose a SAM loopback port: %w", err)
	}
	for attempt := 0; attempt < 1000; attempt++ {
		port := 64000 + (int(start.Int64())+attempt)%1000
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = listener.Close()
		return port, nil
	}
	return 0, errors.New("could not allocate a SAM loopback port in 64000-64999")
}

func writePrivateFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func reapStaleI2PD(pidPath, dataDir string) {
	contents, err := os.ReadFile(pidPath)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(pidPath)
		return
	}
	if !isOwnedI2PD(pid, dataDir) {
		return
	}
	_ = process.Signal(terminationSignal())
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			_ = os.Remove(pidPath)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = process.Kill()
	_ = os.Remove(pidPath)
}
