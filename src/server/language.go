package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/casapps/casspeed/src/common/i18n"
)

type languageContextKey struct{}

type consentCookie struct {
	Essential   bool  `json:"essential"`
	Preferences bool  `json:"preferences"`
	Analytics   bool  `json:"analytics"`
	Timestamp   int64 `json:"timestamp"`
}

func (s *Server) languageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		language := ""
		if requested := r.URL.Query().Get("lang"); requested != "" {
			language = s.resolveConfiguredLanguage(requested)
			if language != "en" || strings.EqualFold(requested, "en") {
				if preferencesConsent(r) {
					secure := strings.HasPrefix(BuildURL(r, "/"), "https://")
					http.SetCookie(w, &http.Cookie{Name: "lang", Value: language, Path: "/", MaxAge: 31536000, SameSite: http.SameSiteLaxMode, Secure: secure})
				}
			}
		}
		if language == "" {
			if cookie, err := r.Cookie("lang"); err == nil && s.isLanguageAvailable(cookie.Value) {
				language = s.resolveConfiguredLanguage(cookie.Value)
			}
		}
		if language == "" {
			if strings.TrimSpace(r.Header.Get("Accept-Language")) == "" && s.Config != nil && s.Config.Server.I18n.DefaultLanguage != "" {
				language = s.resolveConfiguredLanguage(s.Config.Server.I18n.DefaultLanguage)
			} else {
				language = s.detectConfiguredAcceptLanguage(r.Header.Get("Accept-Language"))
			}
		}
		if language == "" {
			language = "en"
		}
		ctx := contextWithLanguage(r, language)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) availableLanguageSet() map[string]struct{} {
	available := make(map[string]struct{})
	if s.Config != nil {
		for _, language := range s.Config.Server.I18n.AvailableLanguages {
			available[strings.ToLower(language)] = struct{}{}
		}
	}
	if len(available) == 0 {
		if locales, err := i18n.Supported(); err == nil {
			for _, locale := range locales {
				available[locale.Language] = struct{}{}
			}
		}
	}
	return available
}

func (s *Server) isLanguageAvailable(language string) bool {
	if !i18n.IsSupportedTag(language) {
		return false
	}
	base := strings.ToLower(strings.SplitN(strings.ReplaceAll(language, "_", "-"), "-", 2)[0])
	_, ok := s.availableLanguageSet()[base]
	return ok
}

func (s *Server) resolveConfiguredLanguage(language string) string {
	if !s.isLanguageAvailable(language) {
		return "en"
	}
	return resolveLanguage(language)
}

func (s *Server) detectConfiguredAcceptLanguage(header string) string {
	type candidate struct {
		tag     string
		quality float64
	}
	var candidates []candidate
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		quality := 1.0
		for _, field := range fields[1:] {
			name, raw, found := strings.Cut(strings.TrimSpace(field), "=")
			if found && strings.EqualFold(name, "q") {
				parsed, err := strconv.ParseFloat(raw, 64)
				if err != nil || parsed <= 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		if len(fields) > 0 && quality > 0 && strings.TrimSpace(fields[0]) != "*" {
			candidates = append(candidates, candidate{tag: fields[0], quality: quality})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].quality > candidates[j].quality })
	for _, item := range candidates {
		if s.isLanguageAvailable(item.tag) {
			return s.resolveConfiguredLanguage(item.tag)
		}
	}
	return "en"
}

func contextWithLanguage(r *http.Request, language string) context.Context {
	return context.WithValue(r.Context(), languageContextKey{}, language)
}

func requestLanguage(r *http.Request) (string, string) {
	language, _ := r.Context().Value(languageContextKey{}).(string)
	if language == "" {
		language = "en"
	}
	catalog, err := i18n.Resolve(language)
	if err != nil {
		return "en", "ltr"
	}
	return catalog.Meta.Language, catalog.Meta.Direction
}

func resolveLanguage(requested string) string {
	return i18n.Normalize(requested)
}

func preferencesConsent(r *http.Request) bool {
	cookie, err := r.Cookie("cookie_consent")
	if err != nil {
		return false
	}
	value, err := url.PathUnescape(cookie.Value)
	if err != nil {
		return false
	}
	var consent consentCookie
	return json.Unmarshal([]byte(value), &consent) == nil && consent.Preferences
}

func (s *Server) serveLocale(w http.ResponseWriter, r *http.Request) {
	language := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/locales/"), ".json")
	data, err := i18n.JSON(language)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}
