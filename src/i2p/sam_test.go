package i2p

import (
	"bufio"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestI2PBase64UsesSAMAlphabet(t *testing.T) {
	value := []byte{0xfb, 0xff, 0xfc}
	encoded := i2pBase64.EncodeToString(value)
	if !strings.ContainsAny(encoded, "-~") {
		t.Fatalf("encoded value %q did not use I2P base64 alphabet", encoded)
	}
	decoded, err := i2pBase64.DecodeString(encoded)
	if err != nil || string(decoded) != string(value) {
		t.Fatalf("I2P base64 round trip = %x, %v", decoded, err)
	}
}

func TestDestinationBytesAndB32Address(t *testing.T) {
	destination := make([]byte, 391)
	destination[0] = 1
	binary.BigEndian.PutUint16(destination[385:387], 4)
	private := make([]byte, len(destination)+64)
	copy(private, destination)
	encoded := i2pBase64.EncodeToString(private)
	got, err := destinationBytes(encoded)
	if err != nil || len(got) != len(destination) {
		t.Fatalf("destinationBytes length = %d, %v", len(got), err)
	}
	wantDigest := sha256.Sum256(destination)
	wantAddress := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(wantDigest[:])) + ".b32.i2p"
	if address := base32Address(got); address != wantAddress {
		t.Fatalf("b32 address = %q, want %q", address, wantAddress)
	}
}

func TestParseSAMReply(t *testing.T) {
	reply := parseSAMReply("SESSION STATUS RESULT=OK DESTINATION=abc")
	if reply.Topic != "SESSION" || reply.Action != "STATUS" || reply.Fields["RESULT"] != "OK" || reply.Fields["DESTINATION"] != "abc" {
		t.Fatalf("parsed SAM reply = %#v", reply)
	}
}

func TestWatchSAMSocketSignalsPeerClosure(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	done := make(chan struct{})
	lost := make(chan struct{})
	go watchSAMSocket(local, bufio.NewReader(local), done, func() { close(lost) })
	_ = remote.Close()
	select {
	case <-lost:
	case <-time.After(time.Second):
		t.Fatal("SAM socket closure was not reported")
	}
	close(done)
}

func TestI2PDConfigDisablesUnusedServices(t *testing.T) {
	content := i2pdConfig(64001, "/var/log/casspeed/i2pd.log")
	for _, required := range []string{"notransit = true", "floodfill = false", "[sam]\nenabled = true", "port = 64001", "[http]\nenabled = false", "[httpproxy]\nenabled = false", "[socksproxy]\nenabled = false", "[bob]\nenabled = false", "[i2cp]\nenabled = false", "[i2pcontrol]\nenabled = false", "[upnp]\nenabled = false"} {
		if !strings.Contains(content, required) {
			t.Errorf("i2pd.conf missing %q", required)
		}
	}
}
