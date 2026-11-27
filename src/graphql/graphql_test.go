package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ReturnsLocalGraphiQLShell(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Handler status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html", rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	for _, want := range []string{"GraphQL Explorer", "/static/vendor/graphiql/", "<noscript>"} {
		if !strings.Contains(body, want) {
			t.Errorf("GraphiQL shell missing %q", want)
		}
	}
	if strings.Contains(body, "cdn.") || strings.Contains(body, "<style") || strings.Contains(body, "<script>") {
		t.Error("GraphiQL shell must use local assets without inline scripts or styles")
	}
}

func TestHandler_LocalizesShellAndPrefixesRoutes(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/edge/server/docs/graphql?lang=ar", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req)
	body := rr.Body.String()
	for _, want := range []string{`<html lang="ar" dir="rtl">`, "/edge/static/css/style.css", `data-endpoint="/edge/api/v1/server/graphql"`, "مستكشف GraphQL"} {
		if !strings.Contains(body, want) {
			t.Errorf("localized GraphiQL shell missing %q", want)
		}
	}
}

func TestQueryHandlerPostUsesConfiguredHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql/query", strings.NewReader(`{"query":"{health{status version}}"}`))
	rr := httptest.NewRecorder()
	handler := NewQueryHandler(Dependencies{Health: func(context.Context) (HealthSnapshot, error) {
		return HealthSnapshot{Status: "ok", Version: "1.2.3"}, nil
	}})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GraphQL POST status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
	for _, want := range []string{`"status":"ok"`, `"version":"1.2.3"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("response missing configured value %s: %s", want, rr.Body.String())
		}
	}
}

func TestQueryHandlerGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/graphql/query?query=%7Bhealth%7Bstatus%7D%7D", nil)
	rr := httptest.NewRecorder()
	handler := NewQueryHandler(Dependencies{Health: func(context.Context) (HealthSnapshot, error) {
		return HealthSnapshot{Status: "ok"}, nil
	}})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Errorf("GraphQL GET response = %d %s", rr.Code, rr.Body.String())
	}
}

func TestQueryHandlerRejectsMutation(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql/query", strings.NewReader(`{"query":"mutation { startSpeedTest { id } }"}`))
	rr := httptest.NewRecorder()
	NewQueryHandler(Dependencies{}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), `"testId":"test-123"`) || !strings.Contains(rr.Body.String(), "errors") {
		t.Errorf("mutation should be rejected by query-only schema, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestSchema_NotEmptyAndReadOnly(t *testing.T) {
	if Schema == "" || !strings.Contains(Schema, "SpeedTest") {
		t.Fatal("GraphQL schema should define speed test reads")
	}
	if strings.Contains(Schema, "type Mutation") {
		t.Fatal("GraphQL schema must remain query-only")
	}
}

func TestSchemaParsesAgainstResolvers(t *testing.T) {
	configuredHandler, ok := NewQueryHandler(Dependencies{}).(*queryHandler)
	if !ok {
		t.Fatal("NewQueryHandler returned an unexpected handler type")
	}
	if configuredHandler.err != nil {
		t.Fatalf("GraphQL schema does not match its resolvers: %v", configuredHandler.err)
	}
}

func TestQueryHandlerRejectsMalformedRequestsAndUnsupportedMethods(t *testing.T) {
	handler := NewQueryHandler(Dependencies{Health: func(context.Context) (HealthSnapshot, error) { return HealthSnapshot{Status: "ok"}, nil }})
	tests := []struct {
		name   string
		method string
		url    string
		body   string
		length int64
		status int
	}{
		{name: "unsupported method", method: http.MethodPut, url: "/graphql", status: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, url: "/graphql", body: "{", status: http.StatusBadRequest},
		{name: "multiple JSON values", method: http.MethodPost, url: "/graphql", body: `{"query":"{health{status}}"} {}`, status: http.StatusBadRequest},
		{name: "invalid GET variables", method: http.MethodGet, url: "/graphql?query=%7Bhealth%7Bstatus%7D%7D&variables=%7Bbad", status: http.StatusBadRequest},
		{name: "body too large", method: http.MethodPost, url: "/graphql", body: `{}`, length: maxGraphQLRequestBytes + 1, status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.url, strings.NewReader(test.body))
			if test.length > 0 {
				request.ContentLength = test.length
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.status, recorder.Body.String())
			}
		})
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/graphql", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "mutations are not supported") {
		t.Fatalf("empty GET response = %d %s", recorder.Code, recorder.Body.String())
	}
}
