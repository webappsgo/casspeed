package server

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/casapps/casspeed/src/common/i18n"
	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/go-chi/chi/v5"
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
var rolePermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,63}$`)
var rolePermissions = []string{"read", "write", "moderate"}
var errRoleChangeRejected = errors.New("role change rejected")

var rolesTemplate = template.Must(template.New("roles").Parse(`<h2>{{.CreateTitle}}</h2><form method="post" action="{{.Path}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="role-name">{{.NameLabel}}</label><input id="role-name" name="name" minlength="2" maxlength="32" pattern="[a-z][a-z0-9_-]*" required><fieldset><legend>{{.PermissionsLabel}}</legend>{{range .Permissions}}<label><input type="checkbox" name="permissions" value="{{.Value}}">{{.Label}}</label>{{end}}</fieldset><button type="submit">{{.CreateButton}}</button></form>{{if .Roles}}<div class="table-wrapper"><table class="data-table"><thead><tr><th scope="col">{{.NameLabel}}</th><th scope="col">{{.PermissionsLabel}}</th><th scope="col">{{.ActionsLabel}}</th></tr></thead><tbody>{{range .Roles}}<tr><td>{{.Name}}</td><td>{{if .CanEdit}}<form method="post" action="{{$.Path}}/{{.Name}}"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><fieldset><legend>{{$.PermissionsLabel}}</legend>{{range .Options}}<label><input type="checkbox" name="permissions" value="{{.Value}}" {{if .Selected}}checked{{end}}>{{.Label}}</label>{{end}}</fieldset><button type="submit">{{$.SaveButton}}</button></form>{{else}}{{.PermissionsText}}{{end}}</td><td>{{if .CanDelete}}<form method="post" action="{{$.Path}}/{{.Name}}/delete"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><button class="btn btn-danger" type="button" popovertarget="delete-role-{{.Name}}">{{$.DeleteButton}}</button><div id="delete-role-{{.Name}}" popover aria-labelledby="delete-role-title-{{.Name}}"><h3 id="delete-role-title-{{.Name}}">{{$.DeleteButton}}</h3><p>{{$.NameLabel}}: {{.Name}}</p><button class="btn btn-secondary" type="button" popovertarget="delete-role-{{.Name}}" popovertargetaction="hide">{{$.Cancel}}</button><button class="btn btn-danger" type="submit">{{$.Confirm}}</button></div></form>{{else}}{{$.ProtectedLabel}}{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<p>{{.Empty}}</p>{{end}}`))

type roleRow struct {
	Name            string
	Options         []rolePermissionRow
	CanDelete       bool
	CanEdit         bool
	PermissionsText string
}

type rolePermissionOption struct {
	Value string
	Label string
}

type rolePermissionRow struct {
	Value    string
	Label    string
	Selected bool
}

func (s *Server) handleRolesPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
			http.Error(w, serverAdminText(r, "admin.legacy.errors.role_security"), http.StatusForbidden)
			return
		}
		name := chi.URLParam(r, "id")
		var err error
		if name == "" {
			name = r.FormValue("name")
			err = s.createRole(name, r.Form["permissions"])
		} else {
			err = s.updateRole(name, r.Form["permissions"])
		}
		if err != nil {
			http.Error(w, serverAdminText(r, "user_admin.role_create_failed"), http.StatusConflict)
			return
		}
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, serverAdminText(r, "errors.http_405_message"), http.StatusMethodNotAllowed)
		return
	}
	language, _ := requestLanguage(r)
	catalog, err := i18n.Resolve(language)
	if err != nil {
		http.Error(w, serverAdminText(r, "user_admin.roles_unavailable"), http.StatusInternalServerError)
		return
	}
	s.configMu.RLock()
	roles := make([]roleRow, 0, len(s.Config.Server.Users.Roles.Available))
	permissionSet := make(map[string]struct{}, len(rolePermissions))
	for _, permission := range rolePermissions {
		permissionSet[permission] = struct{}{}
	}
	for _, configured := range s.Config.Server.Users.Roles.Permissions {
		for _, permission := range configured {
			permissionSet[permission] = struct{}{}
		}
	}
	availablePermissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		availablePermissions = append(availablePermissions, permission)
	}
	sort.Strings(availablePermissions)
	for _, name := range s.Config.Server.Users.Roles.Available {
		permissions := append([]string(nil), s.Config.Server.Users.Roles.Permissions[name]...)
		if name == "admin" {
			permissions = []string{catalog.T("user_admin.role_all_permissions", nil)}
		}
		sort.Strings(permissions)
		options := make([]rolePermissionRow, 0, len(availablePermissions))
		for _, permission := range availablePermissions {
			selected := false
			for _, current := range permissions {
				if current == permission {
					selected = true
					break
				}
			}
			label := permission
			if permission == "read" || permission == "write" || permission == "moderate" {
				label = catalog.T("user_admin.role_permission_"+permission, nil)
			}
			options = append(options, rolePermissionRow{Value: permission, Label: label, Selected: selected})
		}
		roles = append(roles, roleRow{Name: name, Options: options, CanEdit: name != "admin", PermissionsText: strings.Join(permissions, ", "), CanDelete: name != "admin" && name != "user" && name != s.Config.Server.Users.Roles.Default})
	}
	s.configMu.RUnlock()
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	options := make([]rolePermissionOption, 0, len(availablePermissions))
	for _, permission := range availablePermissions {
		label := catalog.T("user_admin.role_permission_"+permission, nil)
		if label == "user_admin.role_permission_"+permission {
			label = permission
		}
		options = append(options, rolePermissionOption{Value: permission, Label: label})
	}
	base := "/server/" + s.Config.Server.AdminPath + "/roles"
	csrf := s.issuePreferenceCSRF(w, r)
	title := catalog.T("user_admin.roles_title", nil)
	content := executeTemplate(rolesTemplate, map[string]any{"Path": base, "CSRF": csrf, "Roles": roles, "Permissions": options, "CreateTitle": catalog.T("user_admin.role_create_title", nil), "CreateButton": catalog.T("user_admin.role_create", nil), "SaveButton": catalog.T("user_admin.role_save", nil), "NameLabel": catalog.T("user_admin.role_name", nil), "PermissionsLabel": catalog.T("user_admin.role_permissions", nil), "ActionsLabel": catalog.T("user_admin.actions", nil), "DeleteButton": catalog.T("user_admin.role_delete", nil), "ProtectedLabel": catalog.T("user_admin.role_protected", nil), "Empty": catalog.T("user_admin.role_empty", nil), "Cancel": catalog.T("common.cancel", nil), "Confirm": catalog.T("common.confirm", nil)})
	s.AdminHandler.RenderContentPage(w, r, title, catalog.T("user_admin.roles_description", nil), content)
}

func (s *Server) handleDeleteRolePage(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPageRequest(r) || r.ParseForm() != nil || !validPreferenceCSRF(r) {
		http.Error(w, serverAdminText(r, "admin.legacy.errors.role_security"), http.StatusForbidden)
		return
	}
	if err := s.deleteRole(r.Context(), chi.URLParam(r, "id")); err != nil {
		http.Error(w, serverAdminText(r, "user_admin.role_delete_failed"), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/server/"+s.Config.Server.AdminPath+"/roles", http.StatusSeeOther)
}

func (s *Server) handleRolesAPI(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	switch r.Method {
	case http.MethodGet:
		s.configMu.RLock()
		defer s.configMu.RUnlock()
		if id != "" {
			permissions, ok := s.roleByNameLocked(id)
			if !ok {
				writeUserJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": serverAdminText(r, "user_admin.role_not_found")})
				return
			}
			writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"name": id, "permissions": permissions}})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": s.rolesLocked()})
	case http.MethodPost:
		var request struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.invalid_request")})
			return
		}
		if err := s.createRole(request.Name, request.Permissions); err != nil {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": serverAdminText(r, "user_admin.role_create_failed")})
			return
		}
		writeUserJSON(w, http.StatusCreated, map[string]any{"ok": true, "data": map[string]any{"name": request.Name, "permissions": request.Permissions}})
	case http.MethodPatch:
		var request struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
			writeUserJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": serverAdminText(r, "admin.legacy.errors.invalid_request")})
			return
		}
		if err := s.updateRole(id, request.Permissions); err != nil {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": serverAdminText(r, "user_admin.role_update_failed")})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"name": id, "permissions": request.Permissions}})
	case http.MethodDelete:
		if err := s.deleteRole(r.Context(), id); err != nil {
			writeUserJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": serverAdminText(r, "user_admin.role_delete_failed")})
			return
		}
		writeUserJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST, PATCH, DELETE")
		writeUserJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": serverAdminText(r, "errors.http_405_message")})
	}
}

func (s *Server) createRole(name string, permissions []string) error {
	if !roleNamePattern.MatchString(name) || !validRolePermissions(permissions) {
		return errRoleChangeRejected
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if _, exists := s.roleByNameLocked(name); exists {
		return errRoleChangeRejected
	}
	old := *s.Config
	old.Server.Users.Roles.Available = append([]string(nil), s.Config.Server.Users.Roles.Available...)
	old.Server.Users.Roles.Permissions = cloneRolePermissions(s.Config.Server.Users.Roles.Permissions)
	s.Config.Server.Users.Roles.Available = append(s.Config.Server.Users.Roles.Available, name)
	if s.Config.Server.Users.Roles.Permissions == nil {
		s.Config.Server.Users.Roles.Permissions = make(map[string][]string)
	}
	s.Config.Server.Users.Roles.Permissions[name] = uniqueSorted(permissions)
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		*s.Config = old
		return err
	}
	return nil
}

func (s *Server) updateRole(name string, permissions []string) error {
	if !roleNamePattern.MatchString(name) || !validRolePermissions(permissions) {
		return errRoleChangeRejected
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if _, exists := s.roleByNameLocked(name); !exists || name == "admin" {
		return errRoleChangeRejected
	}
	old := *s.Config
	old.Server.Users.Roles.Available = append([]string(nil), s.Config.Server.Users.Roles.Available...)
	old.Server.Users.Roles.Permissions = cloneRolePermissions(s.Config.Server.Users.Roles.Permissions)
	if s.Config.Server.Users.Roles.Permissions == nil {
		s.Config.Server.Users.Roles.Permissions = make(map[string][]string)
	}
	s.Config.Server.Users.Roles.Permissions[name] = uniqueSorted(permissions)
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		*s.Config = old
		return err
	}
	return nil
}

func (s *Server) deleteRole(ctx context.Context, name string) error {
	if !roleNamePattern.MatchString(name) || name == "admin" || name == "user" {
		return errRoleChangeRejected
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if name == s.Config.Server.Users.Roles.Default {
		return errRoleChangeRejected
	}
	if _, exists := s.roleByNameLocked(name); !exists {
		return errRoleChangeRejected
	}
	lifecycle, ok := s.Store.(interface {
		ListUsers(context.Context, int, int, string) ([]*model.User, int, error)
	})
	if !ok {
		return errRoleChangeRejected
	}
	for offset := 0; ; offset += 500 {
		users, total, err := lifecycle.ListUsers(ctx, 500, offset, "")
		if err != nil {
			return err
		}
		for _, user := range users {
			if user.Role == name {
				return errRoleChangeRejected
			}
		}
		if offset+len(users) >= total || len(users) == 0 {
			break
		}
	}
	old := *s.Config
	old.Server.Users.Roles.Available = append([]string(nil), s.Config.Server.Users.Roles.Available...)
	old.Server.Users.Roles.Permissions = cloneRolePermissions(s.Config.Server.Users.Roles.Permissions)
	available := s.Config.Server.Users.Roles.Available[:0]
	for _, role := range s.Config.Server.Users.Roles.Available {
		if role != name {
			available = append(available, role)
		}
	}
	s.Config.Server.Users.Roles.Available = available
	delete(s.Config.Server.Users.Roles.Permissions, name)
	if err := config.Save(s.Config, s.ConfigPath); err != nil {
		*s.Config = old
		return err
	}
	return nil
}

func cloneRolePermissions(values map[string][]string) map[string][]string {
	copyValues := make(map[string][]string, len(values))
	for role, permissions := range values {
		copyValues[role] = append([]string(nil), permissions...)
	}
	return copyValues
}

func (s *Server) rolesLocked() []map[string]any {
	roles := make([]map[string]any, 0, len(s.Config.Server.Users.Roles.Available))
	for _, name := range s.Config.Server.Users.Roles.Available {
		permissions, _ := s.roleByNameLocked(name)
		roles = append(roles, map[string]any{"name": name, "permissions": permissions})
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i]["name"].(string) < roles[j]["name"].(string) })
	return roles
}

func (s *Server) roleByNameLocked(name string) ([]string, bool) {
	for _, available := range s.Config.Server.Users.Roles.Available {
		if available == name {
			permissions := append([]string(nil), s.Config.Server.Users.Roles.Permissions[name]...)
			if name == "admin" {
				return []string{"*"}, true
			}
			return permissions, true
		}
	}
	return nil, false
}

func validRolePermissions(permissions []string) bool {
	if len(permissions) == 0 {
		return false
	}
	for _, permission := range permissions {
		if !rolePermissionPattern.MatchString(permission) {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
