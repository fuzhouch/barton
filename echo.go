package barton

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	elog "github.com/labstack/gommon/log"
	"github.com/rs/zerolog/log"
	"github.com/ziflex/lecho/v2"
)

// NewEcho creates an Echo engine attaching default Zerolog.
func NewEcho() *echo.Echo {
	e := echo.New()
	wrapper := lecho.From(log.Logger)
	e.Logger = wrapper
	e.Use(lecho.Middleware(lecho.Config{Logger: wrapper}))
	e.Use(middleware.Recover())

	e.Logger.SetLevel(elog.INFO)
	return e
}
