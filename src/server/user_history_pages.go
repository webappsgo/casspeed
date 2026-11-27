package server

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/go-chi/chi/v5"
)

var userHistoryTemplate = template.Must(template.New("user-history").Parse(`<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.Date}}</th><th scope="col">{{.Download}}</th><th scope="col">{{.Upload}}</th><th scope="col">{{.Ping}}</th><th scope="col">{{.Jitter}}</th><th scope="col">{{.Loss}}</th><th scope="col">{{.Result}}</th></tr></thead><tbody>{{range .Tests}}<tr><td>{{.Timestamp}}</td><td>{{printf "%.2f" .DownloadMbps}} Mbps</td><td>{{printf "%.2f" .UploadMbps}} Mbps</td><td>{{printf "%.2f" .PingMs}} ms</td><td>{{printf "%.2f" .JitterMs}} ms</td><td>{{printf "%.2f" .PacketLoss}}%</td><td><a href="/speed-tests/{{.ID}}">{{$.Result}}</a></td></tr>{{else}}<tr><td colspan="7">{{.Empty}}</td></tr>{{end}}</tbody></table></div><nav aria-label="{{.Pagination}}">{{if .Previous}}<a href="{{.Previous}}">{{.PreviousLabel}}</a>{{end}} {{if .Next}}<a href="{{.Next}}">{{.NextLabel}}</a>{{end}}</nav>`))

var userDevicesTemplate = template.Must(template.New("user-devices").Parse(`<p>{{.Lead}}</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post" action="/devices"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="device-name">{{.Name}}</label><input id="device-name" name="name" maxlength="64" required><button class="btn btn-primary" type="submit">{{.Add}}</button></form>{{if .Devices}}<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.Name}}</th><th scope="col">{{.Created}}</th><th scope="col">{{.LastSeen}}</th><th scope="col">{{.Actions}}</th></tr></thead><tbody>{{range .Devices}}<tr><td>{{.Name}}</td><td>{{.CreatedAt}}</td><td>{{.LastSeen}}</td><td><form method="post" action="/devices/{{.ID}}/delete"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="remove-device-{{.ID}}">{{$.Delete}}</button><div id="remove-device-{{.ID}}" popover aria-labelledby="remove-device-title-{{.ID}}"><h3 id="remove-device-title-{{.ID}}">{{$.Delete}}</h3><p>{{$.Delete}}: {{.Name}}</p><button class="btn btn-secondary" type="button" popovertarget="remove-device-{{.ID}}" popovertargetaction="hide">{{$.Keep}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form></td></tr>{{end}}</tbody></table></div>{{else}}<p class="empty-state">{{.Empty}}</p>{{end}}`))

type devicePageRow struct {
	ID        string
	Name      string
	CreatedAt string
	LastSeen  string
}

func (s *Server) handleUserHistoryPage(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		s.renderPrivatePageError(w, r, http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/login?redirect=%2Fhistory"), http.StatusSeeOther)
		return
	}
	page, err := parsePage(r.URL.Query().Get("page"))
	if err != nil {
		s.renderPrivatePageError(w, r, http.StatusBadRequest)
		return
	}
	const pageSize = 25
	userID := model.UserIDString(identity.User.ID)
	tests, err := s.Store.GetUserSpeedTests(r.Context(), userID, pageSize+1, (page-1)*pageSize)
	if err != nil {
		s.renderPrivatePageError(w, r, http.StatusInternalServerError)
		return
	}
	hasNext := len(tests) > pageSize
	if hasNext {
		tests = tests[:pageSize]
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "History page unavailable", http.StatusInternalServerError)
		return
	}
	previous, next := "", ""
	if page > 1 {
		previous = "/history?page=" + strconv.Itoa(page-1)
	}
	if hasNext {
		next = "/history?page=" + strconv.Itoa(page+1)
	}
	title := catalog.T("user_admin.history_title", nil)
	content := executeTemplate(userHistoryTemplate, map[string]any{"Tests": tests, "Date": catalog.T("user_admin.history_date", nil), "Download": catalog.T("user_admin.history_download", nil), "Upload": catalog.T("user_admin.history_upload", nil), "Ping": catalog.T("user_admin.history_ping", nil), "Jitter": catalog.T("user_admin.history_jitter", nil), "Loss": catalog.T("user_admin.history_loss", nil), "Result": catalog.T("user_admin.history_result", nil), "Empty": catalog.T("user_admin.history_empty", nil), "Pagination": catalog.T("user_admin.page_nav", nil), "Previous": previous, "Next": next, "PreviousLabel": catalog.T("user_admin.history_previous", nil), "NextLabel": catalog.T("user_admin.history_next", nil)})
	pageData := publicPageTemplateData{Title: title, Lead: catalog.T("user_admin.history_nav", nil), NoIndex: true, ContainerClass: "container-lg", Sections: []renderedPageSection{{ID: "user-history", Title: catalog.T("user_admin.history_nav", nil), Content: template.HTML(content)}}}
	s.writePrivateUserPage(w, r, &pageData)
}

func (s *Server) handleUserDevicesPage(w http.ResponseWriter, r *http.Request) {
	identity, err := s.userPageIdentity(r)
	if err != nil {
		s.renderPrivatePageError(w, r, http.StatusInternalServerError)
		return
	}
	if identity == nil || identity.User == nil {
		http.Redirect(w, r, prefixPagePath(requestPathPrefix(r), "/server/auth/login?redirect=%2Fdevices"), http.StatusSeeOther)
		return
	}
	userID := model.UserIDString(identity.User.ID)
	errorMessage := ""
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			s.renderPrivatePageError(w, r, http.StatusForbidden)
			return
		}
		if chi.URLParam(r, "deviceID") != "" {
			device, loadErr := s.Store.GetDevice(r.Context(), chi.URLParam(r, "deviceID"))
			if loadErr != nil {
				s.renderPrivatePageError(w, r, http.StatusInternalServerError)
				return
			}
			if device == nil || device.UserID != userID {
				s.renderPrivatePageError(w, r, http.StatusNotFound)
				return
			}
			if err := s.Store.DeleteDevice(r.Context(), device.ID); err != nil {
				s.renderPrivatePageError(w, r, http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/devices", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" || utf8.RuneCountInString(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
			language, _ := requestLanguage(r)
			catalog, catalogErr := i18n.Resolve(language)
			if catalogErr != nil {
				http.Error(w, "Devices page unavailable", http.StatusInternalServerError)
				return
			}
			errorMessage = catalog.T("user_admin.device_name_invalid", nil)
		} else {
			id, randomErr := randomOpaqueValue()
			if randomErr != nil {
				s.renderPrivatePageError(w, r, http.StatusInternalServerError)
				return
			}
			device := &model.Device{ID: id, UserID: userID, Name: name, LastSeen: time.Now().UTC(), CreatedAt: time.Now().UTC()}
			if err := s.Store.CreateDevice(r.Context(), device); err != nil {
				s.renderPrivatePageError(w, r, http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/devices", http.StatusSeeOther)
			return
		}
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		s.renderPrivatePageError(w, r, http.StatusMethodNotAllowed)
		return
	}
	devices, err := s.Store.GetUserDevices(r.Context(), userID)
	if err != nil {
		s.renderPrivatePageError(w, r, http.StatusInternalServerError)
		return
	}
	rows := make([]devicePageRow, 0, len(devices))
	for _, device := range devices {
		rows = append(rows, devicePageRow{ID: device.ID, Name: device.Name, CreatedAt: device.CreatedAt.UTC().Format(time.RFC3339), LastSeen: device.LastSeen.UTC().Format(time.RFC3339)})
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, "Devices page unavailable", http.StatusInternalServerError)
		return
	}
	title := catalog.T("user_admin.devices_title", nil)
	csrf := s.issuePreferenceCSRF(w, r)
	content := executeTemplate(userDevicesTemplate, map[string]any{"Lead": catalog.T("user_admin.devices_lead", nil), "CSRF": csrf, "Name": catalog.T("user_admin.device_name", nil), "Add": catalog.T("user_admin.device_add", nil), "Delete": catalog.T("user_admin.device_delete", nil), "Confirm": catalog.T("common.confirm", nil), "Keep": catalog.T("common.cancel", nil), "Empty": catalog.T("user_admin.devices_empty", nil), "Created": catalog.T("user_admin.device_created_at", nil), "LastSeen": catalog.T("user_admin.device_last_seen", nil), "Actions": catalog.T("user_admin.actions", nil), "Devices": rows, "Error": errorMessage})
	pageData := publicPageTemplateData{Title: title, Lead: catalog.T("user_admin.devices_lead", nil), NoIndex: true, ContainerClass: "container-lg", CSRFToken: csrf, Sections: []renderedPageSection{{ID: "user-devices", Title: catalog.T("user_admin.devices_nav", nil), Content: template.HTML(content)}}}
	s.writePrivateUserPage(w, r, &pageData)
}

func (s *Server) writePrivateUserPage(w http.ResponseWriter, r *http.Request, page *publicPageTemplateData) {
	if err := s.preparePageChrome(w, r, page); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if err := pageTemplate.Execute(w, page); err != nil {
		return
	}
}
