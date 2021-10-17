package barton

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestEchoNameChange(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	b := NewWebApp("BartonTest")
	assert.Equal(t, "BartonTest", b.appName)
	b.Name("SetANewName")
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
	e, cleanup := NewWebApp("BartonTest").NewEcho()
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

func TestEchoEnablePrometheusNoException(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS512")
	token := newToken(t, "HS512", testKey)

	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy()
	zc.SetGlobalLogger()

	// Cleanup() function must be called at last step to make
	// sure we can create another instance without internal error
	// inside Promethues library complaining duplicated registration
	// attempts. This is because Prometheus registration is done in
	// global namespace.
	e, cleanup := NewWebApp("BartonTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoMiddleware())

	// Prometheus path /metrics is also protected.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Prometheus path /metrics is also protected. This is not a
	// recommended approach but let's set it as current behavior.
	// We will fix it later.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/metrics", nil)
	req2.Header.Set("User-Agent", "Golang_UT")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	e.ServeHTTP(w2, req)
	resp2 := w2.Result()
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body),
		"BartonTest_request_duration_seconds_sum") {
		t.Errorf("PrometheusMetricsNotFound:resp=%s", body)
		return
	}
}

func TestEchoEnablePrometheusBecomeJWTException(t *testing.T) {
	// This is not a real test case, but a demo that shows how we
	// workaround current behavior if we want a protected regular
	// service except /metrics.
	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS512")

	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy()
	zc.SetGlobalLogger()

	e, cleanup := NewWebApp("BartonTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware())
	g.GET("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	// Prometheus path /metrics is not protected
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body),
		"BartonTest_request_duration_seconds_sum") {
		t.Errorf("PrometheusMetricsNotFound:resp=%s", body)
		return
	}

	// Normal path are protected - No JWT is denied
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v1/protected", nil)
	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Normal path are protected - Access granted with JWT
	token := newToken(t, "HS512", testKey)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v1/protected", nil)
	req.Header.Set("Authorization",
		fmt.Sprintf("Bearer %s", token))
	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello!", string(answer))
}
