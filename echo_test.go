package barton

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEchoNameChange(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	b := NewWebAppBuilder("BartonTest")
	assert.Equal(t, "BartonTest", b.appName)
	b.AppName("SetANewName")
	assert.Equal(t, "SetANewName", b.appName)
	e, cleanup := b.NewEcho()
	defer cleanup()

	buf.Reset()
	// Perform an HTTP call
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body),
		"SetANewName_request_duration_seconds_sum") {
		t.Errorf("PrometheusMetricsNotFound:response=%s", body)
		return
	}

}

func TestEchoPrometheusIntegration(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	// Cleanup() function must be called at last step to make
	// sure we can create another instance without internal error
	// inside Promethues library complaining duplicated registration
	// attempts. This is because Prometheus registration is done in
	// global namespace.
	e, cleanup := NewWebAppBuilder("BartonTest").NewEcho()
	defer cleanup()

	// Perform an HTTP call
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body),
		"BartonTest_request_duration_seconds_sum") {
		t.Errorf("PrometheusMetricsNotFound:response=%s", body)
		return
	}
}
