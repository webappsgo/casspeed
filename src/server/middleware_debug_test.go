package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casapps/casspeed/src/mode"
)

func TestDebugMiddlewareRecordsMetricsWhenDebugIsDisabled(t *testing.T) {
	requestCount := expRequestCount.Value()
	requestDuration := expRequestDuration.Value()
	server := &Server{Mode: &mode.State{Mode: mode.Production}}
	handler := server.debugMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	if got := expRequestCount.Value(); got != requestCount+1 {
		t.Errorf("request count = %d, want %d", got, requestCount+1)
	}
	if got := expRequestDuration.Value(); got <= requestDuration {
		t.Errorf("request duration = %f, want greater than %f", got, requestDuration)
	}
}
