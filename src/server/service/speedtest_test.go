package service

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// uuidPattern matches the canonical UUID v4 format.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// shareCodeCharset is the allowed character set for share codes.
const shareCodeCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// ---- GenerateShareCode tests ---------------------------------------------

func TestGenerateShareCode_Length(t *testing.T) {
	code := GenerateShareCode()
	if len(code) != 10 {
		t.Errorf("share code length = %d, want 10", len(code))
	}
}

func TestGenerateShareCode_Charset(t *testing.T) {
	code := GenerateShareCode()
	for _, c := range code {
		if !strings.ContainsRune(shareCodeCharset, c) {
			t.Errorf("share code contains invalid character %q in %q", c, code)
		}
	}
}

func TestGenerateShareCode_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	// Generate enough codes that a collision would be astronomically unlikely
	// if the generator is random, but would happen immediately if it is static.
	for i := 0; i < 100; i++ {
		code := GenerateShareCode()
		if _, dup := seen[code]; dup {
			t.Errorf("duplicate share code %q at iteration %d", code, i)
		}
		seen[code] = struct{}{}
	}
}

// ---- HashIP tests --------------------------------------------------------

func TestHashIP_Deterministic(t *testing.T) {
	// Same input must always produce the same hash.
	h1 := HashIP("192.168.1.1")
	h2 := HashIP("192.168.1.1")
	if h1 != h2 {
		t.Errorf("HashIP is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashIP_IsSHA256Hex(t *testing.T) {
	h := HashIP("10.0.0.1")
	// SHA-256 is 32 bytes = 64 hex chars.
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}
}

func TestHashIP_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := HashIP("1.2.3.4")
	h2 := HashIP("4.3.2.1")
	if h1 == h2 {
		t.Error("different IPs should produce different hashes")
	}
}

func TestHashIP_EmptyString(t *testing.T) {
	// Empty input is allowed; it must return a valid, stable hex string.
	h := HashIP("")
	if len(h) != 64 {
		t.Errorf("empty-input hash length = %d, want 64", len(h))
	}
	if HashIP("") != h {
		t.Error("empty-input hash is not deterministic")
	}
}

func TestHashIP_IPv6(t *testing.T) {
	h := HashIP("::1")
	if len(h) != 64 {
		t.Errorf("IPv6 hash length = %d, want 64", len(h))
	}
}

// ---- GenerateTestID tests ------------------------------------------------

func TestGenerateTestID_IsUUIDv4(t *testing.T) {
	id := GenerateTestID()
	if !uuidPattern.MatchString(id) {
		t.Errorf("GenerateTestID() = %q, want UUID v4 format", id)
	}
}

func TestGenerateTestID_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		id := GenerateTestID()
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate test ID %q at iteration %d", id, i)
		}
		seen[id] = struct{}{}
	}
}

// ---- NewSpeedTestService tests -------------------------------------------

func TestNewSpeedTestService(t *testing.T) {
	svc := NewSpeedTestService(4, 1024)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.maxThreads != 4 {
		t.Errorf("maxThreads = %d, want 4", svc.maxThreads)
	}
	if svc.chunkSize != 1024 {
		t.Errorf("chunkSize = %d, want 1024", svc.chunkSize)
	}
}

// ---- RunTest with 1-second duration (integration smoke test) ------------

func TestRunTest_ShortDuration(t *testing.T) {
	svc := NewSpeedTestService(2, 65536)
	progressChan := make(chan ProgressUpdate, 100)

	result, err := svc.RunTest(1, progressChan)
	if err != nil {
		t.Fatalf("RunTest returned error: %v", err)
	}
	if result == nil {
		t.Fatal("RunTest returned nil result")
	}
	if result.DownloadMbps < 0 {
		t.Errorf("download speed should be non-negative, got %f", result.DownloadMbps)
	}
	if result.UploadMbps < 0 {
		t.Errorf("upload speed should be non-negative, got %f", result.UploadMbps)
	}
	if result.PingMs < 0 {
		t.Errorf("ping should be non-negative, got %f", result.PingMs)
	}
}

// ---- GenerateRandomData tests -------------------------------------------

func TestGenerateRandomData(t *testing.T) {
	svc := NewSpeedTestService(4, 1024)

	rec := &fakeResponseWriter{headers: make(http.Header)}
	svc.GenerateRandomData(rec, 1024)

	if rec.headers.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", rec.headers.Get("Content-Type"))
	}
	if len(rec.body) != 1024 {
		t.Errorf("body length = %d, want 1024", len(rec.body))
	}
}

func TestGenerateRandomData_ZeroSize(t *testing.T) {
	svc := NewSpeedTestService(4, 1024)
	rec := &fakeResponseWriter{headers: make(http.Header)}
	svc.GenerateRandomData(rec, 0)
	if len(rec.body) != 0 {
		t.Errorf("body length = %d, want 0", len(rec.body))
	}
}

type fakeResponseWriter struct {
	headers http.Header
	body    []byte
}

func (f *fakeResponseWriter) Header() http.Header        { return f.headers }
func (f *fakeResponseWriter) WriteHeader(statusCode int) {}
func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	f.body = append(f.body, b...)
	return len(b), nil
}

// ---- ConsumeUploadData tests -------------------------------------------

func TestConsumeUploadData(t *testing.T) {
	svc := NewSpeedTestService(4, 1024)
	payload := bytes.Repeat([]byte("x"), 2048)
	req, _ := http.NewRequest("POST", "/upload", bytes.NewReader(payload))

	n, err := svc.ConsumeUploadData(req)
	if err != nil {
		t.Fatalf("ConsumeUploadData error: %v", err)
	}
	if n != 2048 {
		t.Errorf("consumed %d bytes, want 2048", n)
	}
}

func TestConsumeUploadData_Empty(t *testing.T) {
	svc := NewSpeedTestService(4, 1024)
	req, _ := http.NewRequest("POST", "/upload", bytes.NewReader(nil))
	n, err := svc.ConsumeUploadData(req)
	if err != nil {
		t.Fatalf("ConsumeUploadData error: %v", err)
	}
	if n != 0 {
		t.Errorf("consumed %d bytes, want 0", n)
	}
}
