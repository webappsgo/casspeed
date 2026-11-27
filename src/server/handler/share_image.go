package handler

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
)

type ShareImageHandler struct {
	store store.Store
}

var shareBackground = color.RGBA{R: 15, G: 23, B: 42, A: 255}
var shareCard = color.RGBA{R: 30, G: 41, B: 59, A: 255}
var shareAccent = color.RGBA{R: 45, G: 212, B: 191, A: 255}
var shareText = color.RGBA{R: 248, G: 250, B: 252, A: 255}
var shareMuted = color.RGBA{R: 148, G: 163, B: 184, A: 255}

func NewShareImageHandler(st store.Store) *ShareImageHandler {
	return &ShareImageHandler{store: st}
}

func (h *ShareImageHandler) GetSharePNG(w http.ResponseWriter, r *http.Request) {
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

	if err := h.store.IncrementShareViews(r.Context(), shareCode); err != nil {
		http.Error(w, "Unable to update share count", http.StatusInternalServerError)
		return
	}

	img := image.NewRGBA(image.Rect(0, 0, 1200, 630))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: shareBackground}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(56, 48, 1144, 582), &image.Uniform{C: shareCard}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(56, 48, 66, 582), &image.Uniform{C: shareAccent}, image.Point{}, draw.Src)
	drawText(img, 100, 88, "CASSPEED", shareAccent, 4)
	drawText(img, 100, 175, "DOWNLOAD", shareMuted, 3)
	drawText(img, 100, 218, fmt.Sprintf("%.1f MBPS", test.DownloadMbps), shareText, 6)
	drawText(img, 620, 175, "UPLOAD", shareMuted, 3)
	drawText(img, 620, 218, fmt.Sprintf("%.1f MBPS", test.UploadMbps), shareText, 6)
	drawText(img, 100, 365, "PING", shareMuted, 3)
	drawText(img, 100, 408, fmt.Sprintf("%.1f MS", test.PingMs), shareText, 5)
	drawText(img, 390, 365, "JITTER", shareMuted, 3)
	drawText(img, 390, 408, fmt.Sprintf("%.1f MS", test.JitterMs), shareText, 5)
	drawText(img, 680, 365, "PACKET LOSS", shareMuted, 3)
	drawText(img, 680, 408, fmt.Sprintf("%.1f%%", test.PacketLoss), shareText, 5)
	drawText(img, 100, 515, test.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"), shareMuted, 2)

	buf := new(bytes.Buffer)
	if err := png.Encode(buf, img); err != nil {
		http.Error(w, "Image generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(buf.Bytes())
}

func (h *ShareImageHandler) GetShareSVG(w http.ResponseWriter, r *http.Request) {
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

	if err := h.store.IncrementShareViews(r.Context(), shareCode); err != nil {
		http.Error(w, "Unable to update share count", http.StatusInternalServerError)
		return
	}

	svg := fmt.Sprintf(`<svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="#0f172a"/>
  <rect x="56" y="48" width="1088" height="534" rx="20" fill="#1e293b"/>
  <rect x="56" y="48" width="10" height="534" fill="#2dd4bf"/>
  <text x="100" y="125" font-family="system-ui,sans-serif" font-size="42" font-weight="700" fill="#2dd4bf">CASSPEED</text>
  <text x="100" y="205" font-family="system-ui,sans-serif" font-size="20" fill="#94a3b8">DOWNLOAD</text>
  <text x="100" y="275" font-family="system-ui,sans-serif" font-size="50" font-weight="700" fill="#f8fafc">%.1f MBPS</text>
  <text x="620" y="205" font-family="system-ui,sans-serif" font-size="20" fill="#94a3b8">UPLOAD</text>
  <text x="620" y="275" font-family="system-ui,sans-serif" font-size="50" font-weight="700" fill="#f8fafc">%.1f MBPS</text>
  <text x="100" y="390" font-family="system-ui,sans-serif" font-size="20" fill="#94a3b8">PING</text>
  <text x="100" y="445" font-family="system-ui,sans-serif" font-size="36" font-weight="700" fill="#f8fafc">%.1f MS</text>
  <text x="390" y="390" font-family="system-ui,sans-serif" font-size="20" fill="#94a3b8">JITTER</text>
  <text x="390" y="445" font-family="system-ui,sans-serif" font-size="36" font-weight="700" fill="#f8fafc">%.1f MS</text>
  <text x="680" y="390" font-family="system-ui,sans-serif" font-size="20" fill="#94a3b8">PACKET LOSS</text>
  <text x="680" y="445" font-family="system-ui,sans-serif" font-size="36" font-weight="700" fill="#f8fafc">%.1f%%</text>
  <text x="100" y="535" font-family="system-ui,sans-serif" font-size="16" fill="#94a3b8">%s</text>
</svg>`, test.DownloadMbps, test.UploadMbps, test.PingMs, test.JitterMs, test.PacketLoss, test.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"))

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, svg)
}

func drawText(img *image.RGBA, x, y int, text string, col color.Color, scale int) {
	for _, character := range strings.ToUpper(text) {
		if character == ' ' {
			x += 4 * scale
			continue
		}
		glyph, exists := shareGlyphs[character]
		if !exists {
			x += 4 * scale
			continue
		}
		for row, line := range glyph {
			for column, bit := range line {
				if bit == '1' {
					draw.Draw(img, image.Rect(x+column*scale, y+row*scale, x+(column+1)*scale, y+(row+1)*scale), &image.Uniform{C: col}, image.Point{}, draw.Src)
				}
			}
		}
		x += 4 * scale
	}
}

var shareGlyphs = map[rune][5]string{
	'A': {"010", "101", "111", "101", "101"}, 'B': {"110", "101", "110", "101", "110"},
	'C': {"011", "100", "100", "100", "011"}, 'D': {"110", "101", "101", "101", "110"},
	'E': {"111", "100", "110", "100", "111"}, 'F': {"111", "100", "110", "100", "100"},
	'G': {"011", "100", "101", "101", "011"}, 'H': {"101", "101", "111", "101", "101"},
	'I': {"111", "010", "010", "010", "111"}, 'J': {"001", "001", "001", "101", "010"},
	'K': {"101", "101", "110", "101", "101"}, 'L': {"100", "100", "100", "100", "111"},
	'M': {"101", "111", "111", "101", "101"}, 'N': {"101", "111", "111", "111", "101"},
	'O': {"010", "101", "101", "101", "010"}, 'P': {"110", "101", "110", "100", "100"},
	'Q': {"010", "101", "101", "111", "011"}, 'R': {"110", "101", "110", "101", "101"},
	'S': {"011", "100", "010", "001", "110"}, 'T': {"111", "010", "010", "010", "010"},
	'U': {"101", "101", "101", "101", "111"}, 'V': {"101", "101", "101", "101", "010"},
	'W': {"101", "101", "111", "111", "101"}, 'X': {"101", "101", "010", "101", "101"},
	'Y': {"101", "101", "010", "010", "010"}, 'Z': {"111", "001", "010", "100", "111"},
	'0': {"111", "101", "101", "101", "111"}, '1': {"010", "110", "010", "010", "111"},
	'2': {"110", "001", "010", "100", "111"}, '3': {"110", "001", "010", "001", "110"},
	'4': {"101", "101", "111", "001", "001"}, '5': {"111", "100", "110", "001", "110"},
	'6': {"011", "100", "110", "101", "010"}, '7': {"111", "001", "010", "010", "010"},
	'8': {"010", "101", "010", "101", "010"}, '9': {"010", "101", "011", "001", "110"},
	'.': {"000", "000", "000", "000", "010"}, ':': {"000", "010", "000", "010", "000"},
	'-': {"000", "000", "111", "000", "000"}, '%': {"101", "001", "010", "100", "101"},
}
