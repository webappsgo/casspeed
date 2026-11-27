package swagger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/casapps/casspeed/src/common/i18n"
)

var swaggerPage = template.Must(template.New("swagger").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}" data-theme="{{.Theme}}">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="{{index .Text "description"}}">
	<title>{{index .Text "title"}} — CasSpeed</title>
	<link rel="stylesheet" href="{{.Prefix}}/static/css/theme-dark.css">
	<link rel="stylesheet" href="{{.Prefix}}/static/css/theme-light.css">
	<link rel="stylesheet" href="{{.Prefix}}/static/css/style.css">
	<link rel="stylesheet" href="{{.Prefix}}/static/vendor/swagger-ui/swagger-ui.css">
	<link rel="stylesheet" href="{{.Prefix}}/static/css/swagger-ui-theme.css">
	<script src="{{.Prefix}}/static/js/theme.js"></script>
</head>
<body>
	<a class="skip-link" href="#main-content">{{index .Text "skip_content"}}</a>
	<a class="skip-link" href="#site-navigation">{{index .Text "skip_navigation"}}</a>
	<header class="site-header">
		<a class="site-header__brand" href="{{.Prefix}}/" aria-label="{{index .Text "brand_home"}}">CasSpeed</a>
		<nav id="site-navigation" aria-label="{{index .Text "main_navigation"}}"><a href="{{.Prefix}}/">{{index .Text "speed_test"}}</a><a href="{{.Prefix}}/server/help">{{index .Text "help"}}</a><a href="{{.Prefix}}/server/about">{{index .Text "about"}}</a></nav>
		<div class="site-header__actions"><div class="theme-toggle" role="group" aria-label="{{index .Text "color_theme"}}"><button class="theme-toggle__btn" data-theme-btn="dark" aria-pressed="false" aria-label="{{index .Text "theme_dark"}}" type="button">◐</button><button class="theme-toggle__btn" data-theme-btn="light" aria-pressed="false" aria-label="{{index .Text "theme_light"}}" type="button">◑</button><button class="theme-toggle__btn" data-theme-btn="auto" aria-pressed="false" aria-label="{{index .Text "theme_auto"}}" type="button">◎</button></div></div>
	</header>
	<main id="main-content"><div class="container container-lg">
		<header class="page-header"><h1 class="page-title">{{index .Text "title"}}</h1><p class="page-lead">{{index .Text "lead"}}</p></header>
		<section class="section-card" aria-label="{{index .Text "heading"}}">
			<noscript><p>{{index .Text "no_script"}} <a href="{{.SpecURL}}">{{.SpecURL}}</a>.</p></noscript>
			<div id="swagger-ui" data-spec-url="{{.SpecURL}}" aria-live="polite"></div>
		</section>
	</div></main>
	<footer class="site-footer"><a href="{{.Prefix}}/server/about">{{index .Text "about"}}</a> · <a href="{{.Prefix}}/server/privacy">{{index .Text "footer_privacy"}}</a> · <a href="{{.Prefix}}/server/help">{{index .Text "help"}}</a></footer>
	<script src="{{.Prefix}}/static/vendor/swagger-ui/swagger-ui-bundle.js" defer></script>
	<script src="{{.Prefix}}/static/vendor/swagger-ui/swagger-ui-standalone-preset.js" defer></script>
	<script src="{{.Prefix}}/static/js/swagger-init.js" defer></script>
	<script src="{{.Prefix}}/static/js/app.js" defer></script>
</body>
</html>`))

// Handler serves the Swagger UI
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	catalog := docsCatalog(r)
	prefix := docsPathPrefix(r, []string{"/server/docs/swagger", "/server/swagger", "/docs", "/swagger"})
	data := map[string]any{"Theme": DetectTheme(r), "Lang": catalog.Meta.Language, "Dir": catalog.Meta.Direction, "Prefix": prefix, "SpecURL": absoluteURL(r, prefix+"/api/v1/server/swagger"), "Text": swaggerStandaloneText(catalog)}
	if err := swaggerPage.Execute(w, data); err != nil {
		http.Error(w, "Unable to render API documentation", http.StatusInternalServerError)
	}
}

func docsCatalog(r *http.Request) *i18n.Catalog {
	candidates := []string{r.URL.Query().Get("lang")}
	if cookie, err := r.Cookie("lang"); err == nil {
		candidates = append(candidates, cookie.Value)
	}
	for _, value := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		candidates = append(candidates, strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	for _, candidate := range candidates {
		if i18n.IsSupportedTag(candidate) {
			if catalog, err := i18n.Resolve(candidate); err == nil {
				return catalog
			}
		}
	}
	catalog, _ := i18n.Resolve("en")
	return catalog
}

func docsPathPrefix(r *http.Request, suffixes []string) string {
	path := strings.TrimSuffix(r.URL.EscapedPath(), "/")
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return strings.TrimSuffix(path, suffix)
		}
	}
	return ""
}

func swaggerStandaloneText(catalog *i18n.Catalog) map[string]string {
	keys := []string{"description", "title", "skip_content", "skip_navigation", "brand_home", "main_navigation", "home", "speed_test", "help", "about", "color_theme", "theme_dark", "theme_light", "theme_auto", "lead", "heading", "no_script", "footer_privacy"}
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		values[key] = catalog.T("docs.swagger_standalone."+key, nil)
	}
	return values
}

func absoluteURL(r *http.Request, path string) string {
	prefix := docsPathPrefix(r, []string{"/api/v1/server/swagger", "/server/docs/swagger", "/server/swagger", "/docs", "/swagger"})
	if prefix != "" && !strings.HasPrefix(path, prefix+"/") {
		path = prefix + path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return (&url.URL{Scheme: scheme, Host: r.Host, Path: path}).String()
}

// Operation describes one API route in the shared code-derived OpenAPI registry.
type Operation struct {
	Path         string
	Method       string
	OperationID  string
	Summary      string
	Description  string
	Parameters   []map[string]any
	RequestBody  map[string]any
	Responses    map[string]any
	MCPExcluded  bool
	OperatorOnly bool
	MountedWhen  string
}

// Route is one registered API path and the methods served at that path.
// Path is relative to the OpenAPI server URL, and therefore excludes the API
// base prefix. MountedWhen is set for routes that only exist under a runtime
// option such as debug mode or a metrics alias.
type Route struct {
	Path                string
	Methods             []string
	MountedWhen         string
	ResponseContentType string
}

// OperationRegistry is the single API contract used to serve OpenAPI and build MCP tools.
func OperationRegistry() []Operation {
	stringSchema := map[string]any{"type": "string"}
	objectSchema := map[string]any{"type": "object", "additionalProperties": true}
	body := func(schema map[string]any) map[string]any {
		return map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	binaryBody := map[string]any{"required": true, "content": map[string]any{"application/octet-stream": map[string]any{"schema": map[string]any{"type": "string", "format": "byte"}}}}
	pathParam := func(name string) map[string]any {
		return map[string]any{"name": name, "in": "path", "required": true, "schema": stringSchema}
	}
	queryParam := func(name string, schema map[string]any) map[string]any {
		return map[string]any{"name": name, "in": "query", "required": false, "schema": schema}
	}
	tokenSchema := map[string]any{"type": "object", "required": []string{"name"}, "properties": map[string]any{
		"name":       map[string]any{"type": "string", "minLength": 1, "maxLength": 64},
		"scope":      map[string]any{"type": "string", "enum": []string{"read", "read-write", "global"}},
		"expires_at": map[string]any{"type": "string", "format": "date-time"},
	}, "additionalProperties": false}
	jsonResponse := map[string]any{"200": map[string]any{"description": "Successful response", "content": map[string]any{"application/json": map[string]any{"schema": objectSchema}}}}
	ops := []Operation{
		{Path: "/", Method: "GET", OperationID: "getAPIRoot", Summary: "API root", Description: "Describe the versioned API."},
		{Path: "/server/healthz", Method: "GET", OperationID: "getHealth", Summary: "Health status", Description: "Return server health."},
		{Path: "/server/healthz.json", Method: "GET", OperationID: "getHealthJSON", Summary: "Health status JSON", Description: "Return health in JSON format."},
		{Path: "/server/healthz.txt", Method: "GET", OperationID: "getHealthText", Summary: "Health status text", Description: "Return health in plain text."},
		{Path: "/server/mcp", Method: "POST", OperationID: "mcpEndpoint", Summary: "MCP JSON-RPC endpoint", Description: "Handle stateless MCP Streamable HTTP requests. This route is not exposed as a tool.", RequestBody: body(objectSchema), MCPExcluded: true},
		{Path: "/server/auth/register", Method: "POST", OperationID: "registerUser", Summary: "Register user", Description: "Create a user account.", RequestBody: body(objectSchema), MCPExcluded: true},
		{Path: "/server/auth/login", Method: "POST", OperationID: "loginUser", Summary: "Log in", Description: "Create an authenticated session.", RequestBody: body(objectSchema), MCPExcluded: true},
		{Path: "/server/auth/logout", Method: "POST", OperationID: "logoutUser", Summary: "Log out", Description: "End an authenticated session.", MCPExcluded: true},
		{Path: "/server/auth/password/forgot", Method: "POST", OperationID: "requestPasswordReset", Summary: "Request password reset", Description: "Request a password reset.", RequestBody: body(objectSchema), MCPExcluded: true},
		{Path: "/speed-tests", Method: "POST", OperationID: "startSpeedTest", Summary: "Start speed test", Description: "Initialize a speed test.", RequestBody: body(objectSchema)},
		{Path: "/speed-tests", Method: "GET", OperationID: "listSpeedTests", Summary: "List speed tests", Description: "List the authenticated user's test history.", Parameters: []map[string]any{queryParam("limit", map[string]any{"type": "integer", "minimum": 1, "maximum": 100}), queryParam("offset", map[string]any{"type": "integer", "minimum": 0})}},
		{Path: "/speed-tests/{id}/status", Method: "GET", OperationID: "getSpeedTestStatus", Summary: "Read speed-test progress", Description: "Read or stream speed-test progress.", Parameters: []map[string]any{pathParam("id")}},
		{Path: "/speed-tests/{id}/download", Method: "GET", OperationID: "downloadSpeedTestData", Summary: "Download test data", Description: "Retrieve bounded measurement data.", Parameters: []map[string]any{pathParam("id")}, Responses: binaryResponse("application/octet-stream")},
		{Path: "/speed-tests/{id}/uploads", Method: "POST", OperationID: "uploadSpeedTestData", Summary: "Upload test data", Description: "Submit bounded measurement data encoded as base64.", Parameters: []map[string]any{pathParam("id")}, RequestBody: binaryBody},
		{Path: "/speed-tests/{id}", Method: "GET", OperationID: "getSpeedTestResult", Summary: "Read speed-test result", Description: "Retrieve an owned or public test result.", Parameters: []map[string]any{pathParam("id")}},
		{Path: "/speed-tests/{id}/shares", Method: "POST", OperationID: "createSpeedTestShare", Summary: "Share speed-test result", Description: "Create an explicit share link for an owned result.", Parameters: []map[string]any{pathParam("id")}, RequestBody: body(objectSchema)},
		{Path: "/shares/{code}", Method: "GET", OperationID: "getSharedSpeedTest", Summary: "Read shared speed-test result", Description: "Retrieve fields permitted for a shared result.", Parameters: []map[string]any{pathParam("code")}},
		{Path: "/shares/{code}/images/png", Method: "GET", OperationID: "exportSharedSpeedTestPNG", Summary: "Export shared result image as PNG", Description: "Download a PNG export of a shared speed-test result through the versioned API.", Parameters: []map[string]any{pathParam("code")}, Responses: binaryResponse("image/png")},
		{Path: "/shares/{code}/images/svg", Method: "GET", OperationID: "exportSharedSpeedTestSVG", Summary: "Export shared result image as SVG", Description: "Download an SVG export of a shared speed-test result through the versioned API.", Parameters: []map[string]any{pathParam("code")}, Responses: binaryResponse("image/svg+xml")},
		{Path: "/users", Method: "GET", OperationID: "getUserProfile", Summary: "Read user profile", Description: "Read the authenticated user's profile."},
		{Path: "/users", Method: "PATCH", OperationID: "updateUserProfile", Summary: "Update user profile", Description: "Update profile fields for the authenticated user.", RequestBody: body(objectSchema)},
		{Path: "/users/settings", Method: "GET", OperationID: "getUserSettings", Summary: "Read user settings", Description: "Read privacy, notification, and appearance settings for the authenticated user."},
		{Path: "/users/security", Method: "GET", OperationID: "getUserSecurity", Summary: "Read user security settings", Description: "Read non-secret security state for the authenticated user."},
		{Path: "/users/devices", Method: "GET", OperationID: "listUserDevices", Summary: "List devices", Description: "List the authenticated user's devices."},
		{Path: "/users/devices", Method: "POST", OperationID: "createUserDevice", Summary: "Create device", Description: "Create a device for the authenticated user.", RequestBody: body(objectSchema)},
		{Path: "/users/devices/{deviceId}", Method: "DELETE", OperationID: "deleteUserDevice", Summary: "Delete device", Description: "Delete one of the authenticated user's devices.", Parameters: []map[string]any{pathParam("deviceId")}},
		{Path: "/users/tokens", Method: "GET", OperationID: "listUserTokens", Summary: "List API tokens", Description: "List the authenticated user's token metadata.", MCPExcluded: true},
		{Path: "/users/tokens", Method: "POST", OperationID: "createUserToken", Summary: "Create API token", Description: "Create a new API token.", RequestBody: body(tokenSchema), MCPExcluded: true},
		{Path: "/users/tokens/{tokenId}", Method: "DELETE", OperationID: "revokeUserToken", Summary: "Revoke API token", Description: "Revoke one of the authenticated user's API tokens.", Parameters: []map[string]any{pathParam("tokenId")}, MCPExcluded: true},
		{Path: "/server/{adminPath}/settings", Method: "GET", OperationID: "getServerSettings", Summary: "Read server settings", Description: "Read administrative server settings.", Parameters: []map[string]any{pathParam("adminPath")}, OperatorOnly: true},
		{Path: "/server/{adminPath}/settings", Method: "PUT", OperationID: "updateServerSettings", Summary: "Update server settings", Description: "Update administrative server settings.", Parameters: []map[string]any{pathParam("adminPath")}, RequestBody: body(objectSchema), OperatorOnly: true},
	}
	for i := range ops {
		if ops[i].Responses == nil {
			ops[i].Responses = jsonResponse
		}
	}
	return ops
}

// SpecWithRoutes merges code-authored operation metadata with the API routes
// discovered from the running router. Registered routes without explicit
// metadata still appear as generic operations, so route coverage cannot
// silently depend on a manually maintained list.
func SpecWithRoutes(routes []Route) []Operation {
	operations := make(map[string]Operation)
	for _, operation := range OperationRegistry() {
		operations[operationKey(operation.Method, operation.Path)] = operation
	}
	for _, route := range routes {
		path := normalizeOpenAPIPath(route.Path)
		if path == "" {
			continue
		}
		methods := append([]string(nil), route.Methods...)
		for _, method := range methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if !supportedMethod(method) {
				continue
			}
			key := operationKey(method, path)
			operation, exists := operations[key]
			if !exists {
				var requestBody map[string]any
				if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
					mediaType := "application/json"
					schema := map[string]any{"type": "object", "additionalProperties": true}
					if strings.HasSuffix(path, "/uploads") {
						mediaType = "application/octet-stream"
						schema = map[string]any{"type": "string", "format": "binary"}
					}
					requestBody = map[string]any{"required": true, "content": map[string]any{mediaType: map[string]any{"schema": schema}}}
				}
				operation = Operation{
					Path: path, Method: method,
					OperationID: genericOperationID(method, path),
					Summary:     method + " " + path,
					Description: "Registered API operation. See the server API documentation for authentication and payload details.",
					Parameters:  genericPathParameters(path),
					RequestBody: requestBody,
					Responses:   genericResponses(method, route.ResponseContentType),
				}
			}
			if operation.MountedWhen == "" {
				operation.MountedWhen = route.MountedWhen
			}
			operations[key] = operation
		}
	}
	result := make([]Operation, 0, len(operations))
	for _, operation := range operations {
		result = append(result, operation)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Method < result[j].Method
	})
	return result
}

func normalizeOpenAPIPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" {
		return path
	}
	return strings.TrimSuffix(path, "/")
}

func operationKey(method, path string) string { return strings.ToUpper(method) + " " + path }

func supportedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func genericOperationID(method, path string) string {
	var id strings.Builder
	method = strings.ToLower(method)
	id.WriteString(method)
	upperNext := true
	for _, character := range path {
		if character == '{' {
			id.WriteString("By")
			upperNext = true
			continue
		}
		if character == '}' {
			continue
		}
		if character < '0' || character > '9' && character < 'A' || character > 'Z' && character < 'a' || character > 'z' {
			upperNext = true
			continue
		}
		if upperNext {
			if character >= 'a' && character <= 'z' {
				character -= 'a' - 'A'
			}
			upperNext = false
		}
		id.WriteRune(character)
	}
	if id.Len() == 0 {
		id.WriteString("apiOperation")
	}
	pathHash := sha256.Sum256([]byte(path))
	return id.String() + "_" + hex.EncodeToString(pathHash[:4])
}

func defaultJSONResponses() map[string]any {
	return map[string]any{"200": map[string]any{
		"description": "Successful response",
		"content":     map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "additionalProperties": true}}},
	}}
}

func binaryResponse(contentType string) map[string]any {
	return map[string]any{"200": map[string]any{
		"description": "Successful response",
		"content":     map[string]any{contentType: map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}},
	}}
}

func genericResponses(method, contentType string) map[string]any {
	if method == http.MethodHead || method == http.MethodOptions {
		return map[string]any{"204": map[string]any{"description": "Successful response"}}
	}
	if contentType == "" {
		return defaultJSONResponses()
	}
	return map[string]any{"200": map[string]any{
		"description": "Successful response",
		"content":     map[string]any{contentType: map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}},
	}}
}

func genericPathParameters(path string) []map[string]any {
	parameters := make([]map[string]any, 0)
	for remaining := path; ; {
		start := strings.IndexByte(remaining, '{')
		if start < 0 {
			break
		}
		remaining = remaining[start+1:]
		end := strings.IndexByte(remaining, '}')
		if end < 0 {
			break
		}
		name := remaining[:end]
		if name != "" {
			parameters = append(parameters, map[string]any{
				"name": name, "in": "path", "required": true,
				"schema": map[string]any{"type": "string"},
			})
		}
		remaining = remaining[end+1:]
	}
	return parameters
}

// SpecHandler serves the OpenAPI JSON generated from OperationRegistry.
func SpecHandler(w http.ResponseWriter, r *http.Request) {
	SpecHandlerWithRoutes(w, r, nil)
}

// SpecHandlerWithRoutes serves an OpenAPI document that includes the supplied
// runtime route inventory in addition to annotated operation metadata.
func SpecHandlerWithRoutes(w http.ResponseWriter, r *http.Request, routes []Route) {
	paths := map[string]map[string]any{}
	for _, operation := range SpecWithRoutes(routes) {
		methods := paths[operation.Path]
		if methods == nil {
			methods = map[string]any{}
			paths[operation.Path] = methods
		}
		parameters := operation.Parameters
		entry := map[string]any{
			"operationId":     operation.OperationID,
			"summary":         operation.Summary,
			"description":     operation.Description,
			"responses":       operation.Responses,
			"x-mcp-excluded":  operation.MCPExcluded,
			"x-operator-only": operation.OperatorOnly,
		}
		if len(parameters) > 0 {
			entry["parameters"] = parameters
		}
		if operation.RequestBody != nil {
			entry["requestBody"] = operation.RequestBody
		}
		if operation.MountedWhen != "" {
			entry["x-mounted-when"] = operation.MountedWhen
		}
		methods[strings.ToLower(operation.Method)] = entry
	}
	document := map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]string{"title": "CasSpeed API", "description": "Self-hosted speed testing server API", "version": "1.0.0"},
		"servers": []map[string]string{{"url": absoluteURL(r, "/api/v1"), "description": "API v1"}},
		"paths":   paths,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(document); err != nil {
		http.Error(w, "Unable to encode OpenAPI document", http.StatusInternalServerError)
	}
}
