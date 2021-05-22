package barton

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// LogContent is used to decode log content.
// The columns must be public to allow json package access it.
type LogContent struct {
	Level     string  `json:"level"`
	Host      string  `json:"host"` // Server which sends request
	Node      string  `json:"node"` // Machine which writes log
	Time      string  `json:"time"`
	Status    int     `json:"status"`
	Method    string  `json:"method"`
	Uri       string  `json:"uri"`
	RemoteIP  string  `json:"remote_ip"`
	Latency   float64 `json:"latency"`
	UserAgent string  `json:"user_agent"`
	Message   string  `json:"message"`
}

func TestInitGlobalZeroLogDefaultFields(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("ErrorOnHostname:%s", err.Error())
		return
	}
	buf := bytes.NewBufferString("")

	// Run code
	err = InitGlobalZeroLog(buf)
	if err != nil {
		t.Errorf("ErrorOnGlobalZeroLog:%s", err.Error())
	}

	log.Info().Msg("Test")

	// Parse results
	content := LogContent{}
	err = json.Unmarshal(buf.Bytes(), &content)
	if err != nil {
		t.Errorf("ErrorOnDecodingJSON:%s,val=%s",
			err.Error(), buf.String())
		return
	}

	// Verification
	if content.Level != "info" {
		t.Errorf("Level:expect=info,actual=%s,%s",
			content.Level, buf.String())
		return
	}

	if content.Node != hostname {
		t.Errorf("Host:expect=%s,actual=%s",
			hostname, content.Node)
		return
	}

	_, err = time.Parse(time.RFC3339, content.Time)
	if err != nil {
		t.Errorf("ErrorOnTime.Parse:%s", err.Error())
		return
	}

	if content.Message != "Test" {
		t.Errorf("Message:expect=Test,actual=%s",
			content.Message)
		return
	}
}

func TestInitGlobalZeroLogIgnoreDebug(t *testing.T) {
	buf := bytes.NewBufferString("")
	SetGlobalZeroLogPolicy()
	err := InitGlobalZeroLog(buf)
	if err != nil {
		t.Errorf("ErrorOnGlobalZeroLog:%s", err.Error())
	}

	log.Debug().Msg("IgnoreDebug")

	if buf.String() != "" {
		t.Errorf("IgnoreDebug:actual=%s", buf.String())
		return
	}
}

func TestSetOffGlobalZeroLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	SetOffGlobalZeroLog()

	log.Info().Msg("Test")
	if buf.String() != "" {
		t.Errorf("SetOff:actual=%s", buf.String())
		return
	}
}

func TestEchoAcceptZeroLog(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("ErrorOnHostname:%s", err.Error())
		return
	}

	buf := bytes.NewBufferString("")
	err = InitGlobalZeroLog(buf)
	if err != nil {
		t.Errorf("ErrorOnGlobalZeroLog:%s", err.Error())
	}

	e := NewEcho()
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
	err = json.Unmarshal(buf.Bytes(), &content)
	if err != nil {
		t.Errorf("ErrorOnDecodingJSON:%s,val=%s",
			err.Error(), buf.String())
		return
	}

	// Verification
	if content.Level != "info" {
		t.Errorf("Level:expect=info,actual=%s,%s",
			content.Level, buf.String())
		return
	}

	if content.Node != hostname {
		t.Errorf("Node:expect=%s,actual=%s",
			hostname, content.Host)
		return
	}

	_, err = time.Parse(time.RFC3339, content.Time)
	if err != nil {
		t.Errorf("ErrorOnTime.Parse:%s", err.Error())
		return
	}

	if content.Status != http.StatusMultiStatus {
		t.Errorf("Status:expect=%d,actual=%d,%s",
			http.StatusMultiStatus,
			content.Status,
			buf.String())
		return
	}

	if content.Method != "GET" {
		t.Errorf("Method:expect=GET,actual=%s,%s",
			content.Method,
			buf.String())
		return
	}

	if content.Uri != "/testpath" {
		t.Errorf("Uri:expect=/testpath,actual=%s,%s",
			content.Uri,
			buf.String())
		return
	}

	if content.RemoteIP == "" {
		t.Errorf("RemoteIP:expect=nonEmpty,actual=%s,%s",
			content.RemoteIP,
			buf.String())
		return
	}

	if content.Latency <= 0 {
		t.Errorf("Latency:expect=Positive,actual=%f,%s",
			content.Latency,
			buf.String())
	}

	if content.Uri != "/testpath" {
		t.Errorf("Uri:expect=/testpath,actual=%s,%s",
			content.Uri,
			buf.String())
		return
	}

	if content.UserAgent != "Golang_UT" {
		t.Errorf("UserAgent:expect=Golang_UT,actual=%s,%s",
			content.UserAgent,
			buf.String())
		return
	}

	if content.Message != "" {
		t.Errorf("Message:expectEmpty,actual=%s,%s",
			content.Message,
			buf.String())
		return
	}

}
