package barton

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// LogContent is used to decode log content.
// The columns must be public to allow json package access it.
type LogContent struct {
	Level     string  `json:"level"`
	Host      string  `json:"host"` // Server which sends request
	Time      string  `json:"time"`
	Status    int     `json:"status"`
	Method    string  `json:"method"`
	URI       string  `json:"uri"`
	RemoteIP  string  `json:"remote_ip"`
	Latency   float64 `json:"latency"`
	UserAgent string  `json:"user_agent"`
	Message   string  `json:"message"`
}

func TestInitGlobalZeroLogDefaultFields(t *testing.T) {
	buf := bytes.NewBufferString("")

	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	log.Info().Msg("Test")

	// Parse results
	content := LogContent{}
	err := json.Unmarshal(buf.Bytes(), &content)
	assert.Nil(t, err, "ErrorOnDecodingJSON:%s", buf.String())

	// Verification
	assert.Equal(t, "info", content.Level,
		"Level:expect=info,actual=%s,%s",
		content.Level, buf.String())

	_, err = time.Parse(time.RFC3339, content.Time)
	assert.Nil(t, err, "ErrorOnTime.Parse")
	assert.Equal(t, "Test", content.Message)
}

func TestInitGlobalZeroLogIgnoreDebug(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	log.Debug().Msg("IgnoreDebug")
	assert.Equal(t, "", buf.String(), "IgnoreDebugNotCaptured")
}

func TestSetOffGlobalZeroLog(t *testing.T) {
	buf := bytes.NewBufferString("")

	zc := NewZerologConfig().SetWriter(buf)
	zc.SetGlobalLogger()    // First let's set an real logger
	zc.SetOffGlobalLogger() // Then we disable it.

	log.Info().Msg("Test")
	assert.Equal(t, "", buf.String(), "SetOffWritesLog")
}

func TestEchoAcceptZeroLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	e, cleanup := NewWebApp("BartonTest").NewEcho()
	defer cleanup()

	buf.Reset() // Remove log lines written during Echo app creation.
	e.GET("/testpath", func(c echo.Context) error {
		return c.String(http.StatusMultiStatus, "")
	})

	// Perform an HTTP call
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/testpath", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	// Parse results
	content := LogContent{}
	err := json.Unmarshal(buf.Bytes(), &content)
	assert.Nil(t, err, "ErrorOnDecodingJSON:'%s'", buf.String())

	// Verification
	assert.Equal(t, "info", content.Level,
		"Level:expect=info,actual=%s,%s",
		content.Level, buf.String())

	_, err = time.Parse(time.RFC3339, content.Time)
	assert.Nil(t, err, "ErrorOnTime.Parse")

	assert.Equal(t, http.StatusMultiStatus, content.Status,
		"Status:expect=%d,actual=%d,%s",
		http.StatusMultiStatus, content.Status, buf.String())

	assert.Equal(t, "GET", content.Method,
		"Method:expect=GET,actual=%s,%s",
		content.Method, buf.String())

	assert.Equal(t, "/testpath", content.URI,
		"URI:expect=/testpath,actual=%s,%s",
		content.URI, buf.String())

	assert.NotEqual(t, "", content.RemoteIP,
		"RemoteIP:expect=nonEmpty,actual=%s,%s",
		content.RemoteIP, buf.String())

	assert.True(t, content.Latency > 0,
		"Latency:expect=Positive,actual=%f,%s",
		content.Latency, buf.String())

	assert.Equal(t, "/testpath", content.URI,
		"URI:expect=/testpath,actual=%s,%s",
		content.URI, buf.String())

	assert.Equal(t, "Golang_UT", content.UserAgent,
		"UserAgent:expect=Golang_UT,actual=%s,%s",
		content.UserAgent, buf.String())

	assert.Equal(t, "", content.Message,
		"Message:expectEmpty,actual=%s,%s",
		content.Message, buf.String())
}

func TestUseLocalTime(t *testing.T) {
	buf := bytes.NewBufferString("")

	zc := NewZerologConfig().SetWriter(buf).UseLocalTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	log.Info().Msg("Test")

	// Parse results
	content := LogContent{}
	err := json.Unmarshal(buf.Bytes(), &content)
	assert.Nil(t, err, "ErrorOnDecodingJSON:%s", buf.String())

	ts, err := time.Parse(time.RFC3339, content.Time)
	assert.Nil(t, err, "content.Time.Parse")

	zoneName, offset := ts.Zone()
	expectedZone, expectedOffset := time.Now().Zone()
	assert.Equal(t, expectedZone, zoneName)
	assert.Equal(t, expectedOffset, offset)
}
