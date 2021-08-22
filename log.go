package barton

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ZerologConfig creates an object to configure and set global Zerolog
// object.
type ZerologConfig struct {
	useUTCTime   bool
	targetWriter io.Writer
}

// NewZerologConfig creates a new config object with default settings:
// timestamp written to RFC3339 format, and write to os.Stderr.
func NewZerologConfig() *ZerologConfig {
	return &ZerologConfig{
		useUTCTime:   true,
		targetWriter: os.Stderr,
	}
}

// UseUTCTime forces timezone info to UTC in Zerolog. Need to
// call SetGlobalPolicy() to make it take effect.
func (c *ZerologConfig) UseUTCTime() *ZerologConfig {
	c.useUTCTime = true
	return c
}

// UseLocalTime enforces timezone info added to Zerolog. Need to
// call SetGlobalPolicy() to make it take effect.
func (c *ZerologConfig) UseLocalTime() *ZerologConfig {
	c.useUTCTime = false
	return c
}

// SetWriter sets a writer object (io.Writer) that log lines are written
// to. Note that the io.Writer needs to be closed by caller side if
// any. By default, ZerologConfig sets writer to os.Stderr.
func (c *ZerologConfig) SetWriter(writer io.Writer) *ZerologConfig {
	c.targetWriter = writer
	return c
}

// SetGlobalPolicy sets default zerolog settings used by Gregson.
// The following policy are enforced:
//
// 1. Always use RFC3339 format ("2006-01-02T15:04:05Z07:00")
// 2. Timestamp returns UTC.
// 3. Prints only INFO level logs or above.
// 4. Sampling is disabled.
//
// #1 and #2 are for readability reason, considering develpers may have
// micro-services running in different machines.
//
// Special notes for #3: Log level customization is unrecommended. This
// is to avoid a practice, that developers may write less log in
// production, but more in dev, assuming reported issue can be
// reproduced in-house. This is usually not true for Internet oriented
// services, because issues are triggerred only under high load.
//
// #4 is set by almost same reason with #3. Sampling sacrifaces diagnose
// feasibility to get smaller file size. This is usually not worthy
// in production environment.
func (c *ZerologConfig) SetGlobalPolicy() *ZerologConfig {
	zerolog.TimeFieldFormat = time.RFC3339
	if c.useUTCTime {
		zerolog.TimestampFunc = func() time.Time {
			return time.Now().In(time.UTC)
		}
	} else {
		zerolog.TimestampFunc = time.Now
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.DisableSampling(true)
	return c
}

// SetGlobalLogger creates a logger object and assign it to global
// Zerolog object (log.Logger).
func (c *ZerologConfig) SetGlobalLogger() {
	logger := zerolog.New(c.targetWriter).
		With().
		Timestamp().
		Logger()
	log.Logger = logger
}

// SetOffGlobalLogger configures global zerolog to discard messages.
// This is useful when writing tests, but do not use in production.
func (c *ZerologConfig) SetOffGlobalLogger() {
	log.Logger = zerolog.Nop()
}
