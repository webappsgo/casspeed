package i2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var i2pEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
var i2pBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")

type samReply struct {
	Topic  string
	Action string
	Fields map[string]string
}

func parseSAMReply(line string) samReply {
	fields := make(map[string]string)
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return samReply{Fields: fields}
	}
	reply := samReply{Topic: parts[0], Action: parts[1], Fields: fields}
	for _, part := range parts[2:] {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			fields[key] = strings.Trim(value, `"`)
		}
	}
	return reply
}

func command(conn net.Conn, reader *bufio.Reader, timeout time.Duration, line string) (samReply, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return samReply{}, errors.New("SAM deadline failed")
	}
	defer conn.SetDeadline(time.Time{})
	if _, err := fmt.Fprintln(conn, line); err != nil {
		return samReply{}, errors.New("SAM command write failed")
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		return samReply{}, errors.New("SAM response read failed")
	}
	return parseSAMReply(response), nil
}

func dialSAM(ctx context.Context, address string) (net.Conn, *bufio.Reader, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	reply, err := command(conn, reader, 10*time.Second, "HELLO VERSION MIN=3.1 MAX=3.3")
	if err != nil || reply.Topic != "HELLO" || reply.Action != "REPLY" || reply.Fields["RESULT"] != "OK" {
		_ = conn.Close()
		if err != nil {
			return nil, nil, err
		}
		if reply.Fields["RESULT"] == "NOVERSION" {
			return nil, nil, errors.New("SAM version 3.1 or newer is required")
		}
		return nil, nil, errors.New("SAM HELLO rejected")
	}
	major, minor, ok := samVersion(reply.Fields["VERSION"])
	if !ok || major != 3 || minor < 1 {
		_ = conn.Close()
		return nil, nil, errors.New("SAM version 3.1 or newer is required")
	}
	return conn, reader, nil
}

func samVersion(value string) (int, int, bool) {
	majorText, minorText, ok := strings.Cut(value, ".")
	if !ok {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	return major, minor, majorErr == nil && minorErr == nil
}

func probeSAM(address string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, reader, err := dialSAM(ctx, address)
	if err != nil {
		return false
	}
	_, _ = command(conn, reader, 2*time.Second, "QUIT")
	_ = conn.Close()
	return true
}

func createSession(ctx context.Context, cfg Config, samAddress, keyPath string, backendPort int, listener net.Listener) (net.Conn, net.Conn, *bufio.Reader, *bufio.Reader, string, func() bool, func() bool, error) {
	control, reader, err := dialSAM(ctx, samAddress)
	if err != nil {
		return nil, nil, nil, nil, "", nil, nil, fmt.Errorf("SAM control connection failed: %w", err)
	}
	stopControl := context.AfterFunc(ctx, func() { _ = control.Close() })
	priv, err := loadOrCreateDestination(control, reader, keyPath, cfg.SignatureType)
	if err != nil {
		stopControl()
		_ = control.Close()
		return nil, nil, nil, nil, "", nil, nil, err
	}
	destination, err := destinationBytes(priv)
	if err != nil {
		stopControl()
		_ = control.Close()
		return nil, nil, nil, nil, "", nil, nil, err
	}
	id := fmt.Sprintf("site-%d", os.Getpid())
	var reply samReply
	for attempt := 0; attempt < 2; attempt++ {
		reply, err = command(control, reader, cfg.BootstrapTimeout,
			fmt.Sprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s i2cp.leaseSetEncType=4 inbound.length=%d outbound.length=%d inbound.quantity=%d outbound.quantity=%d",
				id, priv, cfg.InboundLength, cfg.OutboundLength, cfg.InboundQuantity, cfg.OutboundQuantity))
		if err != nil {
			stopControl()
			_ = control.Close()
			return nil, nil, nil, nil, "", nil, nil, errors.New("SESSION CREATE failed or timed out")
		}
		if reply.Fields["RESULT"] == "DUPLICATED_ID" && attempt == 0 {
			id = fmt.Sprintf("%s-%s", id, randomSuffix())
			continue
		}
		break
	}
	if reply.Fields["RESULT"] != "OK" {
		stopControl()
		_ = control.Close()
		if reply.Fields["RESULT"] == "INVALID_KEY" {
			return nil, nil, nil, nil, "", nil, nil, fmt.Errorf("SESSION CREATE rejected the key in %s; the operator must regenerate the address", keyPath)
		}
		if reply.Fields["RESULT"] == "DUPLICATED_DEST" {
			return nil, nil, nil, nil, "", nil, nil, errors.New("SESSION CREATE destination is already in use")
		}
		return nil, nil, nil, nil, "", nil, nil, errors.New("SESSION CREATE rejected by SAM")
	}
	if cfg.BackendReady != nil {
		if err := cfg.BackendReady(listener); err != nil {
			stopControl()
			_ = control.Close()
			return nil, nil, nil, nil, "", nil, nil, fmt.Errorf("start I2P backend: %w", err)
		}
	}
	forward, forwardReader, err := dialSAM(ctx, samAddress)
	if err != nil {
		stopControl()
		_ = control.Close()
		return nil, nil, nil, nil, "", nil, nil, fmt.Errorf("SAM forwarding connection failed: %w", err)
	}
	stopForward := context.AfterFunc(ctx, func() { _ = forward.Close() })
	reply, err = command(forward, forwardReader, 10*time.Second,
		fmt.Sprintf("STREAM FORWARD ID=%s PORT=%d HOST=127.0.0.1 SILENT=true", id, backendPort))
	if err != nil || reply.Fields["RESULT"] != "OK" {
		stopForward()
		stopControl()
		_ = forward.Close()
		_ = control.Close()
		return nil, nil, nil, nil, "", nil, nil, errors.New("STREAM FORWARD failed")
	}
	return control, forward, reader, forwardReader, base32Address(destination), stopControl, stopForward, nil
}

func watchSAMSocket(conn net.Conn, reader *bufio.Reader, done <-chan struct{}, lost func()) {
	for {
		select {
		case <-done:
			return
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			lost()
			return
		}
		if _, err := reader.Peek(1); err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			lost()
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() && line == "" {
				continue
			}
			lost()
			return
		}
		reply := parseSAMReply(line)
		if result := reply.Fields["RESULT"]; result != "" && result != "OK" {
			lost()
			return
		}
	}
}

func randomSuffix() string {
	var bytes [8]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", bytes)
}

func loadOrCreateDestination(conn net.Conn, reader *bufio.Reader, keyPath string, signatureType int) (string, error) {
	encoded, err := os.ReadFile(keyPath)
	if err == nil {
		key := string(encoded)
		if _, err := destinationBytes(key); err != nil {
			return "", fmt.Errorf("invalid I2P destination key file %s", keyPath)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read I2P destination key file %s: %w", keyPath, err)
	}
	reply, err := command(conn, reader, 10*time.Second, fmt.Sprintf("DEST GENERATE SIGNATURE_TYPE=%d", signatureType))
	if err != nil || reply.Topic != "DEST" || reply.Action != "REPLY" || (reply.Fields["RESULT"] != "" && reply.Fields["RESULT"] != "OK") {
		return "", errors.New("DEST GENERATE failed")
	}
	key := reply.Fields["PRIV"]
	if _, err := destinationBytes(key); err != nil {
		return "", errors.New("DEST GENERATE returned an invalid destination key")
	}
	if err := atomicSecretFile(keyPath, []byte(key)); err != nil {
		return "", fmt.Errorf("persist I2P destination key: %w", err)
	}
	return key, nil
}

func atomicSecretFile(path string, value []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".site-keys-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func destinationBytes(priv string) ([]byte, error) {
	raw, err := i2pBase64.DecodeString(priv)
	if err != nil || len(raw) < 387 {
		return nil, errors.New("invalid destination key")
	}
	length := 387 + int(binary.BigEndian.Uint16(raw[385:387]))
	if len(raw) < length {
		return nil, errors.New("truncated destination key")
	}
	return raw[:length], nil
}

func base32Address(destination []byte) string {
	digest := sha256.Sum256(destination)
	return strings.ToLower(i2pEncoding.EncodeToString(digest[:])) + ".b32.i2p"
}
