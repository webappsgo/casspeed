package swagger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- GetThemeCSS tests ---------------------------------------------------

func TestGetThemeCSS_Light(t *testing.T) {
	css := GetThemeCSS("light")
	if !strings.Contains(css, "#ffffff") {
		t.Error("light CSS should contain white background")
	}
}

func TestGetThemeCSS_Dark(t *testing.T) {
	css := GetThemeCSS("dark")
	if !strings.Contains(css, "#1a1a1a") {
		t.Error("dark CSS should contain dark background")
	}
}

func TestGetThemeCSS_Auto(t *testing.T) {
	css := GetThemeCSS("auto")
	if !strings.Contains(css, "prefers-color-scheme") {
		t.Error("auto CSS should contain media queries")
	}
}

func TestGetThemeCSS_Unknown(t *testing.T) {
	css := GetThemeCSS("unknown")
	if css != "" {
		t.Errorf("unknown theme should return empty string, got %q", css)
	}
}

// ---- Handler tests -------------------------------------------------------

func TestHandler_ReturnsHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Handler status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "swagger-ui") {
		t.Error("response body should contain swagger-ui")
	}
}

func TestHandler_ThemeFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs?theme=light", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `data-theme="light"`) {
		t.Error("selected light theme should be applied to the page")
	}
	if strings.Contains(body, "unpkg.com") || strings.Contains(body, "<style") || strings.Contains(body, "<script>") {
		t.Error("Swagger page must use local assets without inline code")
	}
	if !strings.Contains(body, "/static/vendor/swagger-ui/swagger-ui.css") || !strings.Contains(body, "/static/js/swagger-init.js") {
		t.Error("Swagger page should reference its locally hosted assets")
	}
}

func TestHandler_LocalizesShellAndPrefixesRoutes(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/edge/server/docs/swagger?lang=fr", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)
	body := rr.Body.String()
	for _, want := range []string{`<html lang="fr" dir="ltr"`, "/edge/static/css/style.css", `data-spec-url="http://example.com/edge/api/v1/server/swagger"`, "Référence interactive de l’API"} {
		if !strings.Contains(body, want) {
			t.Errorf("localized Swagger shell missing %q", want)
		}
	}
}

// ---- SpecHandler tests ---------------------------------------------------

func TestSpecHandler_ReturnsJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()
	SpecHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("SpecHandler status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "openapi") {
		t.Error("spec should contain 'openapi' field")
	}
	if !strings.Contains(body, `"url":"http://example.com/api/v1"`) {
		t.Errorf("spec server URL should be resolved per request: %s", body)
	}
}

func TestOperationRegistryDrivesOpenAPISpec(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	response := httptest.NewRecorder()
	SpecHandler(response, req)
	var document struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, operation := range OperationRegistry() {
		method := strings.ToLower(operation.Method)
		entry, ok := document.Paths[operation.Path][method]
		if !ok {
			t.Errorf("registry operation %s %s is missing from OpenAPI", operation.Method, operation.Path)
			continue
		}
		id, _ := entry["operationId"].(string)
		if id != operation.OperationID {
			t.Errorf("%s %s operationId = %q, want %q", operation.Method, operation.Path, id, operation.OperationID)
		}
		if seen[id] {
			t.Errorf("duplicate operationId %q", id)
		}
		seen[id] = true
	}
	if len(seen) != len(OperationRegistry()) {
		t.Errorf("OpenAPI has %d unique registry operation IDs, registry contains %d operations", len(seen), len(OperationRegistry()))
	}
}

func TestSpecWithRoutesMergesMetadataAndGeneratesSortedFallbacks(t *testing.T) {
	routes := []Route{
		{Path: "/reports/{reportID}", Methods: []string{"POST", "GET"}, MountedWhen: "server.reports.enabled"},
		{Path: "/reports/{reportID}", Methods: []string{"GET"}},
		{Path: "/speed-tests", Methods: []string{"GET"}},
	}
	operations := SpecWithRoutes(routes)
	if len(operations) != len(OperationRegistry())+2 {
		t.Fatalf("merged operations = %d, want registry %d plus two generated operations", len(operations), len(OperationRegistry()))
	}
	for index := 1; index < len(operations); index++ {
		previous, current := operations[index-1], operations[index]
		if previous.Path > current.Path || previous.Path == current.Path && previous.Method > current.Method {
			t.Fatalf("operations are not deterministically sorted: %#v then %#v", previous, current)
		}
	}
	var generated, annotated bool
	for _, operation := range operations {
		if operation.Path == "/reports/{reportID}" && operation.Method == http.MethodGet {
			generated = true
			if operation.MountedWhen != "server.reports.enabled" || operation.OperationID == "" || operation.Responses == nil {
				t.Fatalf("generated route metadata is incomplete: %#v", operation)
			}
		}
		if operation.Path == "/speed-tests" && operation.Method == http.MethodGet {
			annotated = operation.OperationID == "listSpeedTests"
		}
	}
	if !generated || !annotated {
		t.Fatalf("generated route present=%t, existing metadata preserved=%t", generated, annotated)
	}

	request := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	response := httptest.NewRecorder()
	SpecHandlerWithRoutes(response, request, routes)
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	paths := document["paths"].(map[string]any)
	reportPath := paths["/reports/{reportID}"].(map[string]any)
	get := reportPath["get"].(map[string]any)
	if get["x-mounted-when"] != "server.reports.enabled" {
		t.Fatalf("runtime mount condition missing from OpenAPI operation: %#v", get)
	}
}
