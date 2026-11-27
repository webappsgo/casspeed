package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/metrics"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/service"
	"github.com/casapps/casspeed/src/server/store"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type SpeedTestHandler struct {
	store    store.Store
	service  *service.SpeedTestService
	buildURL func(*http.Request, string) string
	upgrader websocket.Upgrader
}

func (h *SpeedTestHandler) SetURLBuilder(buildURL func(*http.Request, string) string) {
	h.buildURL = buildURL
}

func NewSpeedTestHandler(st store.Store, svc *service.SpeedTestService) *SpeedTestHandler {
	return &SpeedTestHandler{
		store:   st,
		service: svc,
		upgrader: websocket.Upgrader{
			CheckOrigin: sameOrigin,
		},
	}
}

func (h *SpeedTestHandler) StartTest(w http.ResponseWriter, r *http.Request) {
	catalog := handlerCatalog(r)
	testID := service.GenerateTestID()
	userID := authenticatedUserID(h.store, r)
	ownerHash := anonymousOwnerTokenHash(r)
	if userID != "" {
		ownerHash = ""
	} else if ownerHash == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", catalog.T("home.api_errors.start_failed", nil))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "casspeed_owner", Value: base64.RawURLEncoding.EncodeToString(secret), Path: "/", MaxAge: 30 * 24 * 60 * 60, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
		hash := sha256.Sum256(secret)
		ownerHash = hex.EncodeToString(hash[:])
	}
	now := time.Now().UTC()
	test := &model.SpeedTest{ID: testID, UserID: userID, Timestamp: now, ClientIPHash: service.HashIP(r.RemoteAddr), UserAgent: r.UserAgent(), ServerID: "local", OwnerTokenHash: ownerHash, CreatedAt: now}
	if err := h.store.CreateSpeedTest(r.Context(), test); err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", catalog.T("home.api_errors.start_failed", nil))
		return
	}
	durationSeconds, threads, chunkSize := h.service.TestSettings()
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(map[string]interface{}{
		"ok": true,
		"data": map[string]interface{}{
			"test_id":          testID,
			"status":           "started",
			"duration_seconds": durationSeconds,
			"threads":          threads,
			"chunk_size":       chunkSize,
		},
	}, "", "  ")
	w.Write(data)
	w.Write([]byte("\n"))
}

func (h *SpeedTestHandler) TestStatus(w http.ResponseWriter, r *http.Request) {
	catalog := handlerCatalog(r)
	testID := chi.URLParam(r, "id")
	test, ok := h.ownedTest(w, r, testID)
	if !ok {
		return
	}
	if !sameOrigin(r) {
		writeUserError(w, http.StatusForbidden, "FORBIDDEN", catalog.T("home.api_errors.cross_origin", nil))
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	var payload map[string]json.RawMessage
	if err := conn.ReadJSON(&payload); err != nil {
		return
	}
	var messageType string
	if err := json.Unmarshal(payload["type"], &messageType); err != nil || messageType != "result" {
		_ = conn.WriteJSON(map[string]interface{}{"stage": "error", "message": catalog.T("home.api_errors.invalid_result", nil)})
		return
	}
	readMetric := func(name string) (float64, bool) {
		var value float64
		err := json.Unmarshal(payload[name], &value)
		return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	}
	download, downloadOK := readMetric("download_mbps")
	upload, uploadOK := readMetric("upload_mbps")
	ping, pingOK := readMetric("ping_ms")
	jitter, jitterOK := readMetric("jitter_ms")
	loss, lossOK := readMetric("packet_loss")
	if !downloadOK || !uploadOK || !pingOK || !jitterOK || !lossOK || download < 0 || upload < 0 || ping < 0 || jitter < 0 || loss < 0 || loss > 100 || download > 1000000 || upload > 1000000 {
		_ = conn.WriteJSON(map[string]interface{}{"stage": "error", "message": catalog.T("home.api_errors.invalid_result", nil)})
		return
	}
	test.DownloadMbps = download
	test.UploadMbps = upload
	test.PingMs = ping
	test.JitterMs = jitter
	test.PacketLoss = loss
	test.Timestamp = time.Now().UTC()
	if err := h.store.UpdateSpeedTest(r.Context(), test); err != nil {
		_ = conn.WriteJSON(map[string]interface{}{"stage": "error", "message": catalog.T("home.api_errors.save_result_failed", nil)})
		return
	}
	metrics.RecordSpeedTestMetrics(download, upload, ping)
	_ = conn.WriteJSON(service.ProgressUpdate{Stage: "complete", Progress: 1, Message: catalog.T("home.test_complete", nil), TestID: testID, DownloadMbps: download, UploadMbps: upload, PingMs: ping, JitterMs: jitter, PacketLoss: loss})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, r.Host) {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(parsed.Scheme, expectedScheme)
}

func (h *SpeedTestHandler) Download(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.ownedTest(w, r, chi.URLParam(r, "id")); !ok {
		return
	}
	size := 1024 * 1024
	if requested := r.URL.Query().Get("bytes"); requested != "" {
		parsed, err := strconv.Atoi(requested)
		if err != nil || parsed < 64*1024 || parsed > 16*1024*1024 {
			writeUserError(w, http.StatusBadRequest, "INVALID_SIZE", handlerCatalog(r).T("home.api_errors.download_size", nil))
			return
		}
		size = parsed
	}
	h.service.GenerateRandomData(w, size)
}

func (h *SpeedTestHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.ownedTest(w, r, chi.URLParam(r, "id")); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024*1024)
	totalBytes, err := h.service.ConsumeUploadData(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if _, tooLarge := err.(*http.MaxBytesError); tooLarge {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "SERVER_ERROR", "message": handlerCatalog(r).T("home.api_errors.upload_failed", nil),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "data": map[string]int64{"bytes": totalBytes},
	})
}

func (h *SpeedTestHandler) ownedTest(w http.ResponseWriter, r *http.Request, id string) (*model.SpeedTest, bool) {
	if id == "" {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return nil, false
	}
	test, err := h.store.GetSpeedTest(r.Context(), id)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("home.api_errors.load_test_failed", nil))
		return nil, false
	}
	if test == nil {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return nil, false
	}
	userID := authenticatedUserID(h.store, r)
	ownerHash := anonymousOwnerTokenHash(r)
	isUserOwner := userID != "" && test.UserID == userID
	isAnonymousOwner := ownerHash != "" && test.OwnerTokenHash != "" && subtle.ConstantTimeCompare([]byte(ownerHash), []byte(test.OwnerTokenHash)) == 1
	if !isUserOwner && !isAnonymousOwner {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return nil, false
	}
	return test, true
}

func (h *SpeedTestHandler) GetResult(w http.ResponseWriter, r *http.Request) {
	testID := chi.URLParam(r, "id")

	test, err := h.store.GetSpeedTest(r.Context(), testID)
	if err != nil {
		writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("errors.http_500_message", nil))
		return
	}

	if test == nil {
		writeUserError(w, http.StatusNotFound, "NOT_FOUND", handlerCatalog(r).T("errors.http_404_message", nil))
		return
	}

	if test.ShareCode == "" {
		userID := authenticatedUserID(h.store, r)
		ownerHash := anonymousOwnerTokenHash(r)
		isAnonymousOwner := ownerHash != "" && test.OwnerTokenHash != "" && subtle.ConstantTimeCompare([]byte(ownerHash), []byte(test.OwnerTokenHash)) == 1
		if !isAnonymousOwner && (userID == "" || test.UserID == "" || userID != test.UserID) {
			localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
			return
		}
	}
	writePublicResult(w, test)
}

func (h *SpeedTestHandler) CreateShare(w http.ResponseWriter, r *http.Request) {
	testID := chi.URLParam(r, "id")
	test, err := h.store.GetSpeedTest(r.Context(), testID)
	if err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	if test == nil {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return
	}
	userID := authenticatedUserID(h.store, r)
	ownerHash := anonymousOwnerTokenHash(r)
	isAnonymousOwner := ownerHash != "" && test.OwnerTokenHash != "" && subtle.ConstantTimeCompare([]byte(ownerHash), []byte(test.OwnerTokenHash)) == 1
	isAccountOwner := userID != "" && test.UserID != "" && userID == test.UserID
	if !isAnonymousOwner && !isAccountOwner {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return
	}
	if test.ShareCode == "" {
		shareCode, err := service.GenerateShareCode()
		if err != nil {
			writeUserError(w, http.StatusInternalServerError, "SERVER_ERROR", handlerCatalog(r).T("errors.http_500_message", nil))
			return
		}
		test.ShareCode = shareCode
		if err := h.store.UpdateSpeedTest(r.Context(), test); err != nil {
			localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": map[string]string{"code": test.ShareCode, "url": "/shares/" + test.ShareCode}})
}

func anonymousOwnerTokenHash(r *http.Request) string {
	if r.URL.Path == "/mcp" || r.URL.Path == "/api/mcp" || r.URL.Path == "/api/v1/server/mcp" {
		return ""
	}
	cookie, err := r.Cookie("casspeed_owner")
	if err != nil {
		return ""
	}
	secret, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(secret) != 32 {
		return ""
	}
	hash := sha256.Sum256(secret)
	return hex.EncodeToString(hash[:])
}

func authenticatedUserID(st store.Store, r *http.Request) string {
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		const prefix = "Bearer "
		if !strings.HasPrefix(authorization, prefix) {
			return ""
		}
		credential := strings.TrimPrefix(authorization, prefix)
		if !validUserTokenFormat(credential) {
			return ""
		}
		token, err := st.GetAPITokenByToken(r.Context(), credential)
		if err != nil || token == nil || !validUserTokenScope(token.Scope) || token.ExpiresAt != nil && !token.ExpiresAt.After(time.Now()) {
			return ""
		}
		user, err := st.GetUser(r.Context(), token.UserID)
		if err != nil || user == nil {
			return ""
		}
		return model.UserIDString(user.ID)
	}
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/mcp" || r.URL.Path == "/api/mcp" {
		return ""
	}
	cookie, err := r.Cookie("user_session")
	if err != nil || cookie.Value == "" {
		return ""
	}
	session, err := st.GetSession(r.Context(), cookie.Value)
	if err != nil || session == nil || !session.ExpiresAt.After(time.Now()) {
		return ""
	}
	user, err := st.GetUser(r.Context(), session.UserID)
	if err != nil || user == nil {
		return ""
	}
	return model.UserIDString(user.ID)
}

func validUserTokenFormat(token string) bool {
	if len(token) != len("usr_")+32 || !strings.HasPrefix(token, "usr_") {
		return false
	}
	for _, char := range token[len("usr_"):] {
		if !(char >= '0' && char <= '9' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z') {
			return false
		}
	}
	return true
}

func validUserTokenScope(scope string) bool {
	return scope == "global" || scope == "read-write" || scope == "read"
}

func writePublicResult(w http.ResponseWriter, test *model.SpeedTest) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": map[string]interface{}{
		"id": test.ID, "timestamp": test.Timestamp, "download_mbps": test.DownloadMbps,
		"upload_mbps": test.UploadMbps, "ping_ms": test.PingMs, "jitter_ms": test.JitterMs,
		"packet_loss": test.PacketLoss,
	}})
}

func (h *SpeedTestHandler) GetShare(w http.ResponseWriter, r *http.Request) {
	shareCode := chi.URLParam(r, "code")

	test, err := h.store.GetSpeedTestByShareCode(r.Context(), shareCode)
	if err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}

	if test == nil {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return
	}

	if err := h.store.IncrementShareViews(r.Context(), shareCode); err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}

	catalog := handlerCatalog(r)
	prefix := handlerPathPrefix(r, h.buildURL)
	sharePath := "/shares/" + shareCode
	pageRoute := handlerPrefixPath(prefix, sharePath)
	pngRoute := handlerPrefixPath(prefix, sharePath+"/images/png")
	svgRoute := handlerPrefixPath(prefix, sharePath+"/images/svg")
	pageURL, imageURL := pageRoute, pngRoute
	if h.buildURL != nil {
		pageURL = h.buildURL(r, sharePath)
		imageURL = h.buildURL(r, sharePath+"/images/png")
	}
	language := catalog.Meta.Language
	labels := map[string]string{
		"title": catalog.T("result_page.title", nil), "skip": catalog.T("nav.skip_to_content", nil),
		"brand": catalog.T("home.brand", nil), "main_navigation": catalog.T("nav.main_navigation", nil),
		"home": catalog.T("nav.home", nil), "help": catalog.T("pages.help", nil), "privacy": catalog.T("pages.privacy", nil),
		"about": catalog.T("pages.about", nil), "color_theme": catalog.T("home.color_theme", nil),
		"theme_dark": catalog.T("home.theme_dark", nil), "theme_light": catalog.T("home.theme_light", nil),
		"theme_auto": catalog.T("home.theme_auto", nil), "measurements": catalog.T("result_page.measurements", nil),
		"download": catalog.T("result_page.download", nil), "upload": catalog.T("result_page.upload", nil),
		"ping": catalog.T("result_page.ping", nil), "jitter": catalog.T("result_page.jitter", nil),
		"packet_loss": catalog.T("result_page.packet_loss", nil), "tested": catalog.T("result_page.tested", nil),
		"image": catalog.T("result_page.image", nil), "download_png": catalog.T("result_page.download_png", nil),
		"download_svg": catalog.T("result_page.download_svg", nil), "preferences": catalog.T("home.preferences", nil),
	}
	description := catalog.T("result_page.share_description", map[string]string{
		"download": fmt.Sprintf("%.1f", test.DownloadMbps), "upload": fmt.Sprintf("%.1f", test.UploadMbps), "ping": fmt.Sprintf("%.1f", test.PingMs),
	})
	direction := catalog.Meta.Direction
	date := test.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	page := template.Must(template.New("shared-result").Parse(`<!doctype html><html lang="{{.Language}}" dir="{{.Direction}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{index .Labels "title"}} — CasSpeed</title><meta name="description" content="{{.Description}}"><link rel="canonical" href="{{.PageURL}}"><meta property="og:title" content="{{index .Labels "title"}} — CasSpeed"><meta property="og:description" content="{{.Description}}"><meta property="og:image" content="{{.ImageURL}}"><meta property="og:url" content="{{.PageURL}}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{{index .Labels "title"}} — CasSpeed"><meta name="twitter:description" content="{{.Description}}"><meta name="twitter:image" content="{{.ImageURL}}"><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-dark.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/theme-light.css"><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"><script src="{{.BasePath}}/static/js/theme.js"></script></head><body><a class="skip-link" href="#main-content">{{index .Labels "skip"}}</a><header class="site-header"><a class="site-header__brand" href="{{.BasePath}}/" aria-label="{{index .Labels "brand"}}">CasSpeed</a><nav aria-label="{{index .Labels "main_navigation"}}"><a href="{{.BasePath}}/">{{index .Labels "home"}}</a><a href="{{.BasePath}}/server/help">{{index .Labels "help"}}</a></nav><div class="theme-toggle" role="group" aria-label="{{index .Labels "color_theme"}}"><button class="theme-toggle__btn" data-theme-btn="dark" aria-pressed="false" aria-label="{{index .Labels "theme_dark"}}" type="button">◐</button><button class="theme-toggle__btn" data-theme-btn="light" aria-pressed="false" aria-label="{{index .Labels "theme_light"}}" type="button">◑</button><button class="theme-toggle__btn" data-theme-btn="auto" aria-pressed="false" aria-label="{{index .Labels "theme_auto"}}" type="button">◎</button></div></header><main id="main-content"><div class="container container-md"><header class="page-header"><h1 class="page-title">{{index .Labels "title"}}</h1></header><section class="section-card" aria-label="{{index .Labels "measurements"}}"><dl class="health-details"><dt>{{index .Labels "download"}}</dt><dd>{{.Download}} Mbps</dd><dt>{{index .Labels "upload"}}</dt><dd>{{.Upload}} Mbps</dd><dt>{{index .Labels "ping"}}</dt><dd>{{.Ping}} ms</dd><dt>{{index .Labels "jitter"}}</dt><dd>{{.Jitter}} ms</dd><dt>{{index .Labels "packet_loss"}}</dt><dd>{{.PacketLoss}}%</dd><dt>{{index .Labels "tested"}}</dt><dd><time>{{.Tested}}</time></dd></dl></section><section class="section-card" aria-label="{{index .Labels "image"}}"><h2>{{index .Labels "image"}}</h2><p><a href="{{.PNGRoute}}">{{index .Labels "download_png"}}</a> · <a href="{{.SVGRoute}}">{{index .Labels "download_svg"}}</a></p></section></div></main><footer class="site-footer"><a href="{{.BasePath}}/server/privacy">{{index .Labels "privacy"}}</a> · <a href="{{.BasePath}}/server/about">{{index .Labels "about"}}</a> · <a href="{{.BasePath}}/server/preferences#language">{{index .Labels "preferences"}}</a></footer></body></html>`))
	data := struct {
		Language, Direction, BasePath, Description, PageURL, ImageURL, PNGRoute, SVGRoute string
		Download, Upload, Ping, Jitter, PacketLoss, Tested                                string
		Labels                                                                            map[string]string
	}{language, direction, prefix, description, pageURL, imageURL, pngRoute, svgRoute,
		fmt.Sprintf("%.1f", test.DownloadMbps), fmt.Sprintf("%.1f", test.UploadMbps), fmt.Sprintf("%.1f", test.PingMs),
		fmt.Sprintf("%.1f", test.JitterMs), fmt.Sprintf("%.1f", test.PacketLoss), date, labels}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = page.Execute(w, data)
}

func (h *SpeedTestHandler) GetShareAPI(w http.ResponseWriter, r *http.Request) {
	shareCode := chi.URLParam(r, "code")
	test, err := h.store.GetSpeedTestByShareCode(r.Context(), shareCode)
	if err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	if test == nil {
		localizedHTTPError(w, r, http.StatusNotFound, "errors.http_404_message")
		return
	}
	if err := h.store.IncrementShareViews(r.Context(), shareCode); err != nil {
		localizedHTTPError(w, r, http.StatusInternalServerError, "errors.http_500_message")
		return
	}
	writePublicResult(w, test)
}

func (h *SpeedTestHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	userID := authenticatedUserID(h.store, r)
	if userID == "" {
		localizedHTTPError(w, r, http.StatusUnauthorized, "auth.pages.authentication_required")
		return
	}
	tests, err := h.store.GetUserSpeedTests(r.Context(), userID, 50, 0)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "SERVER_ERROR", "message": handlerCatalog(r).T("home.api_errors.start_failed", nil),
		})
		return
	}

	if tests == nil {
		tests = []*model.SpeedTest{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": tests})
}
