package barton

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEchoCreate(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	// Cleanup() function must be called at last step to make
	// sure we can create another instance without internal error
	// inside Promethues library complaining duplicated registration
	// attempts. This is because Prometheus registration is done in
	// global namespace.
	e, cleanup := NewWebAppBuilder().AppName("BartonTest").NewEcho()
	defer cleanup()

	// Perform an HTTP call
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "BartonTest_request_duration_seconds_sum") {
		t.Errorf("PrometheusMetricsNotFound:response=%s", body)
		return
	}
}
