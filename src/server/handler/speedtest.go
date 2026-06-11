package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type SpeedTestHandler struct {
	store   store.Store
	service *service.SpeedTestService
	upgrader websocket.Upgrader
}

func NewSpeedTestHandler(st store.Store, svc *service.SpeedTestService) *SpeedTestHandler {
	return &SpeedTestHandler{
		store:   st,
		service: svc,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (h *SpeedTestHandler) StartTest(w http.ResponseWriter, r *http.Request) {
	testID := service.GenerateTestID()
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(map[string]interface{}{
		"ok": true,
		"data": map[string]string{
			"test_id": testID,
			"status":  "started",
		},
	}, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *SpeedTestHandler) TestStatus(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	progressChan := make(chan service.ProgressUpdate, 10)

	go func() {
		result, _ := h.service.RunTest(10, progressChan)

		testID := service.GenerateTestID()
		shareCode := ""
		if r.URL.Query().Get("share") != "false" {
			shareCode = service.GenerateShareCode()
		}

		test := &model.SpeedTest{
			ID:           testID,
			Timestamp:    time.Now(),
			DownloadMbps: result.DownloadMbps,
			UploadMbps:   result.UploadMbps,
			PingMs:       result.PingMs,
			JitterMs:     result.JitterMs,
			PacketLoss:   result.PacketLoss,
			ClientIPHash: service.HashIP(r.RemoteAddr),
			UserAgent:    r.UserAgent(),
			ShareCode:    shareCode,
			CreatedAt:    time.Now(),
		}

		h.store.CreateSpeedTest(r.Context(), test)

		// Send complete message with all result fields so the frontend can display them
		finalUpdate := service.ProgressUpdate{
			Stage:        "complete",
			Progress:     1.0,
			Message:      "Test complete",
			TestID:       testID,
			ShareCode:    shareCode,
			DownloadMbps: result.DownloadMbps,
			UploadMbps:   result.UploadMbps,
			PingMs:       result.PingMs,
			JitterMs:     result.JitterMs,
			PacketLoss:   result.PacketLoss,
		}
		progressChan <- finalUpdate
		close(progressChan)
	}()

	for update := range progressChan {
		if err := conn.WriteJSON(update); err != nil {
			return
		}
	}
}

func (h *SpeedTestHandler) Download(w http.ResponseWriter, r *http.Request) {
	size := 10 * 1024 * 1024
	h.service.GenerateRandomData(w, size)
}

func (h *SpeedTestHandler) Upload(w http.ResponseWriter, r *http.Request) {
	totalBytes, err := h.service.ConsumeUploadData(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "SERVER_ERROR", "message": "Upload failed",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "data": map[string]int64{"bytes": totalBytes},
	})
}

func (h *SpeedTestHandler) GetResult(w http.ResponseWriter, r *http.Request) {
	testID := chi.URLParam(r, "id")

	test, err := h.store.GetSpeedTest(r.Context(), testID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "SERVER_ERROR", "message": "Internal server error",
		})
		return
	}

	if test == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "NOT_FOUND", "message": "Resource not found",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": test})
}

func (h *SpeedTestHandler) GetShare(w http.ResponseWriter, r *http.Request) {
	shareCode := chi.URLParam(r, "code")

	test, err := h.store.GetSpeedTestByShareCode(r.Context(), shareCode)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if test == nil {
		http.Error(w, "Share not found", http.StatusNotFound)
		return
	}

	h.store.IncrementShareViews(r.Context(), shareCode)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Speed Test Result - casspeed</title>
    <meta property="og:image" content="/s/%s.png">
  </head>
  <body>
    <h1>Speed Test Result</h1>
    <p>Download: %.1f Mbps</p>
    <p>Upload: %.1f Mbps</p>
    <p>Ping: %.1f ms</p>
    <p>Tested: %s</p>
  </body>
</html>
`, shareCode, test.DownloadMbps, test.UploadMbps, test.PingMs, test.Timestamp.Format("2006-01-02 15:04:05"))
}

func (h *SpeedTestHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	// Public recent results (anonymous — no auth needed for public leaderboard)
	// Authenticated users get their own history via session (future: auth middleware)
	tests, err := h.store.GetUserSpeedTests(r.Context(), "", 50, 0)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "SERVER_ERROR", "message": "Internal server error",
		})
		return
	}

	if tests == nil {
		tests = []*model.SpeedTest{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": tests})
}
