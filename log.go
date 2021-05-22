package barton

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// NewZerolog returns an Zerolog object with pre-configured settings.
// It's not exposed. Developers should always call InitGlobalZeroLog()
// instead.
func newZerolog(toFile io.Writer) (zerolog.Logger, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return zerolog.New(nil), err
	}

	logger := zerolog.New(toFile).
		With().
		Timestamp().
		Str("node", hostname).
		Logger()
	return logger, nil
}

// SetGlobalZeroLogPolicy sets default zerolog settings used by Gregson.
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
func SetGlobalZeroLogPolicy() {
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().In(time.UTC)
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.DisableSampling(true)
}

// InitGlobalZeroLog sets global zerolog with default settings.
func InitGlobalZeroLog(toFile io.Writer) error {
	logger, err := newZerolog(toFile)
	if err != nil {
		return err
	}
	log.Logger = logger
	return nil
}

// SetOffGlobalZeroLog configures global zerolog to discard messages.
// This is useful when writing tests, but do not use in production.
func SetOffGlobalZeroLog() {
	log.Logger = zerolog.Nop()
}
