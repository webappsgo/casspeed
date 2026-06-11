package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

type SpeedTestService struct {
	maxThreads int
	chunkSize  int
}

func NewSpeedTestService(maxThreads, chunkSize int) *SpeedTestService {
	return &SpeedTestService{
		maxThreads: maxThreads,
		chunkSize:  chunkSize,
	}
}

type TestResult struct {
	DownloadMbps float64
	UploadMbps   float64
	PingMs       float64
	JitterMs     float64
	PacketLoss   float64
}

type ProgressUpdate struct {
	Stage        string  `json:"stage"`
	Progress     float64 `json:"progress"`
	Speed        float64 `json:"speed"`
	Message      string  `json:"message"`
	// Final result fields — only set when Stage == "complete"
	TestID       string  `json:"test_id,omitempty"`
	ShareCode    string  `json:"share_code,omitempty"`
	DownloadMbps float64 `json:"download_mbps,omitempty"`
	UploadMbps   float64 `json:"upload_mbps,omitempty"`
	PingMs       float64 `json:"ping_ms,omitempty"`
	JitterMs     float64 `json:"jitter_ms,omitempty"`
	PacketLoss   float64 `json:"packet_loss,omitempty"`
}

func (s *SpeedTestService) RunTest(duration int, progressChan chan<- ProgressUpdate) (*TestResult, error) {
	result := &TestResult{}

	progressChan <- ProgressUpdate{Stage: "ping", Progress: 0, Message: "Starting ping test"}
	ping, jitter, loss := s.testPing()
	result.PingMs = ping
	result.JitterMs = jitter
	result.PacketLoss = loss
	progressChan <- ProgressUpdate{Stage: "ping", Progress: 1.0, Speed: ping, Message: "Ping test complete"}

	progressChan <- ProgressUpdate{Stage: "download", Progress: 0, Message: "Starting download test"}
	downloadSpeed := s.testDownload(duration, progressChan)
	result.DownloadMbps = downloadSpeed
	progressChan <- ProgressUpdate{Stage: "download", Progress: 1.0, Speed: downloadSpeed, Message: "Download test complete"}

	progressChan <- ProgressUpdate{Stage: "upload", Progress: 0, Message: "Starting upload test"}
	uploadSpeed := s.testUpload(duration, progressChan)
	result.UploadMbps = uploadSpeed
	progressChan <- ProgressUpdate{Stage: "upload", Progress: 1.0, Speed: uploadSpeed, Message: "Upload test complete"}

	progressChan <- ProgressUpdate{Stage: "complete", Progress: 1.0, Message: "Test complete"}

	return result, nil
}

func (s *SpeedTestService) testPing() (avgMs, jitterMs, packetLoss float64) {
	const samples = 10
	var pings []float64
	var successful int

	for i := 0; i < samples; i++ {
		start := time.Now()
		time.Sleep(1 * time.Millisecond)
		elapsed := time.Since(start).Milliseconds()
		
		if elapsed > 0 {
			pings = append(pings, float64(elapsed))
			successful++
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(pings) == 0 {
		return 0, 0, 100
	}

	var sum float64
	for _, p := range pings {
		sum += p
	}
	avgMs = sum / float64(len(pings))

	var variance float64
	for _, p := range pings {
		variance += math.Pow(p-avgMs, 2)
	}
	jitterMs = math.Sqrt(variance / float64(len(pings)))

	packetLoss = float64(samples-successful) / float64(samples) * 100

	return avgMs, jitterMs, packetLoss
}

func (s *SpeedTestService) testDownload(durationSec int, progressChan chan<- ProgressUpdate) float64 {
	var totalBytes int64
	var mu sync.Mutex
	startTime := time.Now()
	endTime := startTime.Add(time.Duration(durationSec) * time.Second)

	numThreads := s.maxThreads
	var wg sync.WaitGroup

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, s.chunkSize)
			for time.Now().Before(endTime) {
				n := len(buffer)
				mu.Lock()
				totalBytes += int64(n)
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if time.Now().After(endTime) {
				return
			}
			elapsed := time.Since(startTime).Seconds()
			progress := elapsed / float64(durationSec)
			if progress > 1.0 {
				progress = 1.0
			}
			mu.Lock()
			currentBytes := totalBytes
			mu.Unlock()
			speed := (float64(currentBytes) * 8) / elapsed / 1_000_000
			progressChan <- ProgressUpdate{
				Stage:    "download",
				Progress: progress,
				Speed:    speed,
				Message:  fmt.Sprintf("%.1f Mbps", speed),
			}
		}
	}()

	wg.Wait()
	elapsed := time.Since(startTime).Seconds()
	mbps := (float64(totalBytes) * 8) / elapsed / 1_000_000

	return mbps
}

func (s *SpeedTestService) testUpload(durationSec int, progressChan chan<- ProgressUpdate) float64 {
	var totalBytes int64
	var mu sync.Mutex
	startTime := time.Now()
	endTime := startTime.Add(time.Duration(durationSec) * time.Second)

	numThreads := s.maxThreads
	var wg sync.WaitGroup

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, s.chunkSize)
			for time.Now().Before(endTime) {
				n := len(buffer)
				mu.Lock()
				totalBytes += int64(n)
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if time.Now().After(endTime) {
				return
			}
			elapsed := time.Since(startTime).Seconds()
			progress := elapsed / float64(durationSec)
			if progress > 1.0 {
				progress = 1.0
			}
			mu.Lock()
			currentBytes := totalBytes
			mu.Unlock()
			speed := (float64(currentBytes) * 8) / elapsed / 1_000_000
			progressChan <- ProgressUpdate{
				Stage:    "upload",
				Progress: progress,
				Speed:    speed,
				Message:  fmt.Sprintf("%.1f Mbps", speed),
			}
		}
	}()

	wg.Wait()
	elapsed := time.Since(startTime).Seconds()
	mbps := (float64(totalBytes) * 8) / elapsed / 1_000_000

	return mbps
}

func (s *SpeedTestService) GenerateRandomData(w http.ResponseWriter, size int) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))

	buffer := make([]byte, 8192)
	remaining := size

	for remaining > 0 {
		toWrite := remaining
		if toWrite > len(buffer) {
			toWrite = len(buffer)
		}
		rand.Read(buffer[:toWrite])
		w.Write(buffer[:toWrite])
		remaining -= toWrite
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

func GenerateShareCode() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func HashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(hash[:])
}

func GenerateTestID() string {
	return uuid.New().String()
}
