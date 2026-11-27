package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/google/uuid"
)

type SpeedTestService struct {
	maxThreads int
	chunkSize  int
	duration   int
	randomData []byte
}

func NewSpeedTestService(maxThreads, chunkSize int, duration ...int) *SpeedTestService {
	if maxThreads < 1 {
		maxThreads = 4
	}
	if maxThreads > 16 {
		maxThreads = 16
	}
	if chunkSize < 1 {
		chunkSize = 1024 * 1024
	}
	if chunkSize > 16*1024*1024 {
		chunkSize = 16 * 1024 * 1024
	}
	durationSeconds := 10
	if len(duration) > 0 && duration[0] >= 1 && duration[0] <= 120 {
		durationSeconds = duration[0]
	}
	randomData := make([]byte, 64*1024)
	_, _ = rand.Read(randomData)
	return &SpeedTestService{
		maxThreads: maxThreads,
		chunkSize:  chunkSize,
		duration:   durationSeconds,
		randomData: randomData,
	}
}

func (s *SpeedTestService) TestSettings() (durationSeconds, threads, chunkSize int) {
	return s.duration, s.maxThreads, s.chunkSize
}

type ProgressUpdate struct {
	Stage    string  `json:"stage"`
	Progress float64 `json:"progress"`
	Speed    float64 `json:"speed"`
	Message  string  `json:"message"`
	// Final result fields — only set when Stage == "complete"
	TestID       string  `json:"test_id,omitempty"`
	ShareCode    string  `json:"share_code,omitempty"`
	DownloadMbps float64 `json:"download_mbps,omitempty"`
	UploadMbps   float64 `json:"upload_mbps,omitempty"`
	PingMs       float64 `json:"ping_ms,omitempty"`
	JitterMs     float64 `json:"jitter_ms,omitempty"`
	PacketLoss   float64 `json:"packet_loss,omitempty"`
}

func (s *SpeedTestService) GenerateRandomData(w http.ResponseWriter, size int) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	remaining := size
	for remaining > 0 {
		for offset := 0; offset < len(s.randomData) && remaining > 0; offset += 8192 {
			toWrite := len(s.randomData) - offset
			if toWrite > 8192 {
				toWrite = 8192
			}
			if toWrite > remaining {
				toWrite = remaining
			}
			if _, err := w.Write(s.randomData[offset : offset+toWrite]); err != nil {
				return
			}
			remaining -= toWrite
		}
	}
}

func (s *SpeedTestService) ConsumeUploadData(r *http.Request) (int64, error) {
	var totalBytes int64
	buffer := make([]byte, 8192)

	for {
		n, err := r.Body.Read(buffer)
		totalBytes += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalBytes, err
		}
	}

	return totalBytes, nil
}

func GenerateShareCode() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	limit := big.NewInt(int64(len(charset)))
	code := make([]byte, 8)
	for i := range code {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		code[i] = charset[index.Int64()]
	}
	return string(code), nil
}

func HashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(hash[:])
}

func GenerateTestID() string {
	return uuid.New().String()
}
