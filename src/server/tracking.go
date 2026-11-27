package server

import (
	"encoding/json"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/casapps/casspeed/src/config"
)

type trackingMarkup struct{ tags, body, scriptHost, connectHost, imageHost string }

func configuredTracking(cfg config.TrackingConfig) trackingMarkup {
	id := html.EscapeString(cfg.ID)
	base := strings.TrimSuffix(cfg.URL, "/")
	switch cfg.Type {
	case "google":
		if strings.HasPrefix(cfg.ID, "G-") {
			return trackingMarkup{tags: `<script async src="https://www.googletagmanager.com/gtag/js?id=` + url.QueryEscape(cfg.ID) + `"></script>`, body: "window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());gtag('config'," + jsTrackingString(cfg.ID) + ");", scriptHost: "https://www.googletagmanager.com", connectHost: "https://www.google-analytics.com"}
		}
		return trackingMarkup{tags: `<script async src="https://www.google-analytics.com/analytics.js"></script>`, body: "window.ga=window.ga||function(){(ga.q=ga.q||[]).push(arguments)};ga.l=+new Date;ga('create'," + jsTrackingString(cfg.ID) + ",'auto');ga('send','pageview');", scriptHost: "https://www.google-analytics.com", connectHost: "https://www.google-analytics.com"}
	case "matomo", "piwik":
		return trackingMarkup{tags: `<script async src="` + html.EscapeString(base) + `/matomo.js"></script>`, body: "var _paq=window._paq=window._paq||[];_paq.push(['trackPageView']);_paq.push(['enableLinkTracking']);_paq.push(['setTrackerUrl'," + jsTrackingString(base+"/matomo.php") + "]);_paq.push(['setSiteId'," + jsTrackingString(cfg.ID) + "]);", scriptHost: originOf(base), connectHost: originOf(base)}
	case "owa":
		return trackingMarkup{tags: `<script async src="` + html.EscapeString(base) + `/modules/base/js/owa.tracker-combined-min.js"></script>`, body: "OWATracker.setSiteId(" + jsTrackingString(cfg.ID) + ");OWATracker.trackPageView();", scriptHost: originOf(base), connectHost: originOf(base)}
	case "fathom":
		src, host := "https://cdn.usefathom.com/script.js", "https://cdn.usefathom.com"
		if cfg.URL != "" {
			src, host = base+"/tracker.js", originOf(base)
		}
		return trackingMarkup{tags: `<script defer src="` + html.EscapeString(src) + `" data-site="` + id + `"></script>`, scriptHost: host, connectHost: host}
	case "plausible":
		src, host := "https://plausible.io/js/script.js", "https://plausible.io"
		if cfg.URL != "" {
			src, host = base+"/js/script.js", originOf(base)
		}
		return trackingMarkup{tags: `<script defer data-domain="` + id + `" src="` + html.EscapeString(src) + `"></script>`, scriptHost: host, connectHost: host}
	case "umami":
		return trackingMarkup{tags: `<script defer src="` + html.EscapeString(base) + `/script.js" data-website-id="` + id + `"></script>`, scriptHost: originOf(base), connectHost: originOf(base)}
	case "simple":
		return trackingMarkup{tags: `<script async defer src="https://scripts.simpleanalyticscdn.com/latest.js"></script>`, scriptHost: "https://scripts.simpleanalyticscdn.com", connectHost: "https://queue.simpleanalyticscdn.com", imageHost: "https://queue.simpleanalyticscdn.com"}
	case "cloudflare":
		return trackingMarkup{tags: `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"` + id + `"}'></script>`, scriptHost: "https://static.cloudflareinsights.com", connectHost: "https://cloudflareinsights.com"}
	}
	return trackingMarkup{}
}

func jsTrackingString(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }
func originOf(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (s *Server) trackingAllowed(r *http.Request) bool {
	s.configMu.RLock()
	if s.Config == nil {
		s.configMu.RUnlock()
		return false
	}
	tracking := s.Config.Server.Tracking
	analyticsEnabled := s.Config.Server.Privacy.Cookies.Analytics.Enabled
	s.configMu.RUnlock()
	if tracking.Type == "" || tracking.Type == "none" || !analyticsEnabled {
		return false
	}
	if strings.HasSuffix(strings.ToLower(r.Host), ".onion") || strings.HasSuffix(strings.ToLower(r.Host), ".i2p") {
		return false
	}
	consent := readConsent(r)
	return consent.Analytics && consent.Timestamp > 0
}

func (s *Server) trackingScriptHandler(w http.ResponseWriter, r *http.Request) {
	if !s.trackingAllowed(r) {
		http.NotFound(w, r)
		return
	}
	s.configMu.RLock()
	tracking := s.Config.Server.Tracking
	s.configMu.RUnlock()
	body := configuredTracking(tracking).body
	if body == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write([]byte(body))
}

func (s *Server) trackingPageMarkup(r *http.Request) template.HTML {
	if !s.trackingAllowed(r) {
		return ""
	}
	s.configMu.RLock()
	tracking := s.Config.Server.Tracking
	s.configMu.RUnlock()
	provider := configuredTracking(tracking)
	if provider.tags == "" {
		return ""
	}
	markup := provider.tags
	if provider.body != "" {
		markup += `<script async src="/server/tracking.js"></script>`
	}
	return template.HTML(markup)
}

func (s *Server) trackingNoscript(r *http.Request) template.HTML {
	if !s.trackingAllowed(r) {
		return ""
	}
	s.configMu.RLock()
	trackingType := s.Config.Server.Tracking.Type
	s.configMu.RUnlock()
	if trackingType != "simple" {
		return ""
	}
	return template.HTML(`<noscript><img src="https://queue.simpleanalyticscdn.com/noscript.gif" alt="" referrerpolicy="no-referrer-when-downgrade"></noscript>`)
}
