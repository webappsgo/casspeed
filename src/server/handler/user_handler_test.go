package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/go-chi/chi/v5"
)

func serveUserRoute(method, routePath, requestPath string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.MethodFunc(method, routePath, handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, requestPath, nil))
	return recorder
}

func TestUserHandlerGetProfile(t *testing.T) {
	store := newMockStore()
	store.users["user-1"] = &model.User{ID: "user-1", Username: "alice", Email: "alice@example.com"}
	handler := NewUserHandler(store)

	recorder := serveUserRoute(http.MethodGet, "/users/{id}", "/users/user-1", handler.GetProfile)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "alice@example.com") {
		t.Errorf("profile response = %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = serveUserRoute(http.MethodGet, "/users/{id}", "/users/unknown", handler.GetProfile)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("missing profile status = %d, want 404", recorder.Code)
	}

	store.errGetUser = errDB
	recorder = serveUserRoute(http.MethodGet, "/users/{id}", "/users/user-1", handler.GetProfile)
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("database failure status = %d, want 500", recorder.Code)
	}
}

func TestUserHandlerDeviceOperations(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)

	createRouter := chi.NewRouter()
	createRouter.Post("/users/{id}/devices", handler.CreateDevice)
	createReq := httptest.NewRequest(http.MethodPost, "/users/user-1/devices", strings.NewReader(`{"name":"laptop"}`))
	createRec := httptest.NewRecorder()
	createRouter.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("CreateDevice status = %d, want 200", createRec.Code)
	}
	if device := store.devices["device-laptop"]; device == nil || device.UserID != "user-1" {
		t.Fatalf("created device = %#v", device)
	}

	listRouter := chi.NewRouter()
	listRouter.Get("/users/{id}/devices", handler.ListDevices)
	listRec := httptest.NewRecorder()
	listRouter.ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/users/user-1/devices", nil))
	var devices []model.Device
	if err := json.Unmarshal(listRec.Body.Bytes(), &devices); err != nil {
		t.Fatalf("decode devices: %v", err)
	}
	if len(devices) != 1 || devices[0].Name != "laptop" {
		t.Errorf("listed devices = %#v", devices)
	}

	deleteRouter := chi.NewRouter()
	deleteRouter.Delete("/devices/{deviceId}", handler.DeleteDevice)
	deleteRec := httptest.NewRecorder()
	deleteRouter.ServeHTTP(deleteRec, httptest.NewRequest(http.MethodDelete, "/devices/device-laptop", nil))
	if deleteRec.Code != http.StatusOK {
		t.Errorf("DeleteDevice status = %d, want 200", deleteRec.Code)
	}
	if _, exists := store.devices["device-laptop"]; exists {
		t.Error("device should be removed after deletion")
	}
}

func TestUserHandlerDeviceErrors(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)

	badJSON := chi.NewRouter()
	badJSON.Post("/users/{id}/devices", handler.CreateDevice)
	badRec := httptest.NewRecorder()
	badJSON.ServeHTTP(badRec, httptest.NewRequest(http.MethodPost, "/users/user-1/devices", strings.NewReader("{")))
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("malformed CreateDevice status = %d, want 400", badRec.Code)
	}

	store.errCreateDevice = errDB
	createRouter := chi.NewRouter()
	createRouter.Post("/users/{id}/devices", handler.CreateDevice)
	createRec := httptest.NewRecorder()
	createRouter.ServeHTTP(createRec, httptest.NewRequest(http.MethodPost, "/users/user-1/devices", strings.NewReader(`{"name":"tablet"}`)))
	if createRec.Code != http.StatusInternalServerError {
		t.Errorf("CreateDevice store failure status = %d, want 500", createRec.Code)
	}

	store.errGetUserDevices = errDB
	listRec := serveUserRoute(http.MethodGet, "/users/{id}/devices", "/users/user-1/devices", handler.ListDevices)
	if listRec.Code != http.StatusInternalServerError {
		t.Errorf("ListDevices store failure status = %d, want 500", listRec.Code)
	}

	store.errDeleteDevice = errDB
	deleteRouter := chi.NewRouter()
	deleteRouter.Delete("/devices/{deviceId}", handler.DeleteDevice)
	deleteRec := httptest.NewRecorder()
	deleteRouter.ServeHTTP(deleteRec, httptest.NewRequest(http.MethodDelete, "/devices/device-1", nil))
	if deleteRec.Code != http.StatusInternalServerError {
		t.Errorf("DeleteDevice store failure status = %d, want 500", deleteRec.Code)
	}
}

func TestUserHandlerTokenOperations(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)

	createRouter := chi.NewRouter()
	createRouter.Post("/users/{id}/tokens", handler.CreateToken)
	createRec := httptest.NewRecorder()
	createRouter.ServeHTTP(createRec, httptest.NewRequest(http.MethodPost, "/users/user-2/tokens", strings.NewReader(`{"name":"automation"}`)))
	if createRec.Code != http.StatusOK {
		t.Fatalf("CreateToken status = %d, want 200", createRec.Code)
	}
	if len(store.tokens) != 1 {
		t.Fatalf("stored token count = %d, want 1", len(store.tokens))
	}
	for _, token := range store.tokens {
		if token.UserID != "user-2" || token.Name != "automation" || !strings.HasPrefix(token.Token, "key_") {
			t.Errorf("stored token = %#v", token)
		}
	}

	listRouter := chi.NewRouter()
	listRouter.Get("/users/{id}/tokens", handler.ListTokens)
	listRec := httptest.NewRecorder()
	listRouter.ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/users/user-2/tokens", nil))
	var tokens []model.APIToken
	if err := json.Unmarshal(listRec.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].Name != "automation" {
		t.Errorf("listed tokens = %#v", tokens)
	}

	var tokenID string
	for id := range store.tokens {
		tokenID = id
	}
	revokeRouter := chi.NewRouter()
	revokeRouter.Delete("/tokens/{tokenId}", handler.RevokeToken)
	revokeRec := httptest.NewRecorder()
	revokeRouter.ServeHTTP(revokeRec, httptest.NewRequest(http.MethodDelete, "/tokens/"+tokenID, nil))
	if revokeRec.Code != http.StatusOK {
		t.Errorf("RevokeToken status = %d, want 200", revokeRec.Code)
	}
	if len(store.tokens) != 0 {
		t.Error("token should be removed after revocation")
	}
}

func TestUserHandlerTokenErrors(t *testing.T) {
	store := newMockStore()
	handler := NewUserHandler(store)

	badJSON := chi.NewRouter()
	badJSON.Post("/users/{id}/tokens", handler.CreateToken)
	badRec := httptest.NewRecorder()
	badJSON.ServeHTTP(badRec, httptest.NewRequest(http.MethodPost, "/users/user-1/tokens", strings.NewReader("{")))
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("malformed CreateToken status = %d, want 400", badRec.Code)
	}

	store.errCreateAPIToken = errDB
	createRouter := chi.NewRouter()
	createRouter.Post("/users/{id}/tokens", handler.CreateToken)
	createRec := httptest.NewRecorder()
	createRouter.ServeHTTP(createRec, httptest.NewRequest(http.MethodPost, "/users/user-1/tokens", strings.NewReader(`{"name":"api"}`)))
	if createRec.Code != http.StatusInternalServerError {
		t.Errorf("CreateToken store failure status = %d, want 500", createRec.Code)
	}

	store.errGetUserAPITokens = errDB
	listRec := serveUserRoute(http.MethodGet, "/users/{id}/tokens", "/users/user-1/tokens", handler.ListTokens)
	if listRec.Code != http.StatusInternalServerError {
		t.Errorf("ListTokens store failure status = %d, want 500", listRec.Code)
	}

	store.errDeleteAPIToken = errDB
	revokeRouter := chi.NewRouter()
	revokeRouter.Delete("/tokens/{tokenId}", handler.RevokeToken)
	revokeRec := httptest.NewRecorder()
	revokeRouter.ServeHTTP(revokeRec, httptest.NewRequest(http.MethodDelete, "/tokens/token-1", nil))
	if revokeRec.Code != http.StatusInternalServerError {
		t.Errorf("RevokeToken store failure status = %d, want 500", revokeRec.Code)
	}
}
