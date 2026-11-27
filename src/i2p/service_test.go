package i2p

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartServicePersistsKeyAndUsesSilentForwardSocket(t *testing.T) {
	bridge, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	private := make([]byte, 455)
	private[0] = 1
	binary.BigEndian.PutUint16(private[385:387], 4)
	privateValue := i2pBase64.EncodeToString(private)
	var generated, sessions, forwardCommands atomic.Int32
	go func() {
		for {
			connection, err := bridge.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					switch {
					case strings.HasPrefix(line, "HELLO "):
						_, _ = fmt.Fprintln(conn, "HELLO REPLY RESULT=OK VERSION=3.3")
					case strings.HasPrefix(line, "DEST GENERATE "):
						generated.Add(1)
						_, _ = fmt.Fprintf(conn, "DEST REPLY PUB=public PRIV=%s\n", privateValue)
					case strings.HasPrefix(line, "SESSION CREATE "):
						sessions.Add(1)
						if strings.Contains(line, "DESTINATION=PRIV=") {
							return
						}
						_, _ = fmt.Fprintln(conn, "SESSION STATUS RESULT=OK")
					case strings.HasPrefix(line, "STREAM FORWARD "):
						if strings.Contains(line, "SILENT=true") && strings.Contains(line, "HOST=127.0.0.1") {
							forwardCommands.Add(1)
						}
						_, _ = fmt.Fprintln(conn, "STREAM STATUS RESULT=OK")
					case line == "QUIT":
						return
					}
				}
			}(connection)
		}
	}()

	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SAMAddress = bridge.Addr().String()
	cfg.ConfigDir = filepath.Join(root, "config")
	cfg.DataDir = filepath.Join(root, "data")
	cfg.LogDir = filepath.Join(root, "log")
	cfg.BootstrapTimeout = 30 * time.Second
	firstAddress, firstKey := createTestSession(t, cfg, bridge.Addr().String())
	info, err := os.Stat(filepath.Join(cfg.DataDir, "i2p", "site", "site-keys.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || strings.Contains(string(firstKey), "\n") {
		t.Fatalf("destination key mode/content = %o %q", info.Mode().Perm(), firstKey)
	}
	secondAddress, secondKey := createTestSession(t, cfg, bridge.Addr().String())
	if secondAddress != firstAddress {
		t.Fatalf("address changed across restart: %q != %q", secondAddress, firstAddress)
	}
	if string(secondKey) != string(firstKey) {
		t.Fatal("destination key changed across restart")
	}
	if generated.Load() != 1 || sessions.Load() != 2 || forwardCommands.Load() != 2 {
		t.Fatalf("SAM calls generate=%d sessions=%d silent forwards=%d", generated.Load(), sessions.Load(), forwardCommands.Load())
	}
}

func createTestSession(t *testing.T, cfg Config, address string) (string, []byte) {
	t.Helper()
	if err := ensureDirs(cfg); err != nil {
		t.Fatal(err)
	}
	listener, err := allocateBackendListener()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	control, forward, _, _, b32, stopControl, stopForward, err := createSession(context.Background(), cfg, address, filepath.Join(cfg.DataDir, "i2p", "site", "site-keys.dat"), port, listener)
	if err != nil {
		t.Fatalf("create SAM session: %v", err)
	}
	if stopForward != nil {
		stopForward()
	}
	if stopControl != nil {
		stopControl()
	}
	_ = forward.Close()
	_ = control.Close()
	key, err := os.ReadFile(filepath.Join(cfg.DataDir, "i2p", "site", "site-keys.dat"))
	if err != nil {
		t.Fatal(err)
	}
	return b32, key
}

func TestValidateConfigRejectsInvalidTunnelSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigDir, cfg.DataDir, cfg.LogDir = "config", "data", "logs"
	cfg.InboundLength = 8
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("invalid tunnel length was accepted")
	}
}
