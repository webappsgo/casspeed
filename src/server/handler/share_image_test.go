package handler

import (
	"bytes"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/go-chi/chi/v5"
)

func serveShareImage(method, route, requestPath string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.MethodFunc(method, route, handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, requestPath, nil))
	return recorder
}

func TestShareImageGetSharePNG(t *testing.T) {
	store := newMockStore()
	store.testsByCode["ABC123"] = &model.SpeedTest{
		ShareCode:    "ABC123",
		DownloadMbps: 123.4,
		UploadMbps:   56.7,
		PingMs:       12.3,
		Timestamp:    time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	handler := NewShareImageHandler(store)
	recorder := serveShareImage(http.MethodGet, "/share/{code}.png", "/share/ABC123.png", handler.GetSharePNG)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GetSharePNG status = %d, want 200", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "image/png" || recorder.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("image headers = %#v", recorder.Header())
	}
	img, err := png.Decode(bytes.NewReader(recorder.Body.Bytes()))
	if err != nil {
		t.Fatalf("decode PNG response: %v", err)
	}
	if got := img.Bounds().Size(); got.X != 1200 || got.Y != 630 {
		t.Errorf("PNG dimensions = %v, want 1200x630", got)
	}
	if store.testsByCode["ABC123"].ShareViews != 1 {
		t.Errorf("share views = %d, want incremented once", store.testsByCode["ABC123"].ShareViews)
	}
}

func TestShareImageGetShareSVG(t *testing.T) {
	store := newMockStore()
	store.testsByCode["SVG123"] = &model.SpeedTest{
		ShareCode:    "SVG123",
		DownloadMbps: 42.5,
		UploadMbps:   10.0,
		PingMs:       8.2,
		Timestamp:    time.Date(2024, time.June, 7, 8, 9, 10, 0, time.UTC),
	}
	handler := NewShareImageHandler(store)
	recorder := serveShareImage(http.MethodGet, "/s/{code}.svg", "/s/SVG123.svg", handler.GetShareSVG)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GetShareSVG status = %d, want 200", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "image/svg+xml" || recorder.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("image headers = %#v", recorder.Header())
	}
	for _, text := range []string{"<svg width=\"1200\" height=\"630\"", "Download: 42.5 Mbps", "Upload: 10.0 Mbps", "Ping: 8.2 ms", "2024-06-07 08:09:10"} {
		if !strings.Contains(recorder.Body.String(), text) {
			t.Errorf("SVG response is missing %q", text)
		}
	}
	if store.testsByCode["SVG123"].ShareViews != 1 {
		t.Errorf("share views = %d, want incremented once", store.testsByCode["SVG123"].ShareViews)
	}
}

func TestShareImageHandlersReportMissingAndStoreErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request string
		handler func(*ShareImageHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "PNG", request: "/share/{code}.png", handler: (*ShareImageHandler).GetSharePNG},
		{name: "SVG", request: "/share/{code}.svg", handler: (*ShareImageHandler).GetShareSVG},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, failure := range []struct {
				name string
				err  error
				want int
			}{
				{name: "missing result", want: http.StatusNotFound},
				{name: "database failure", err: errDB, want: http.StatusInternalServerError},
			} {
				t.Run(failure.name, func(t *testing.T) {
					store := newMockStore()
					store.errGetByShareCode = failure.err
					handler := NewShareImageHandler(store)
					router := chi.NewRouter()
					router.MethodFunc(http.MethodGet, tt.request, func(w http.ResponseWriter, r *http.Request) {
						tt.handler(handler, w, r)
					})
					path := strings.ReplaceAll(tt.request, "{code}", "missing")
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
					if recorder.Code != failure.want {
						t.Errorf("status = %d, want %d", recorder.Code, failure.want)
					}
				})
			}
		})
	}
}
