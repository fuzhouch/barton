package barton

import (
	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	elog "github.com/labstack/gommon/log"
	pg "github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/ziflex/lecho/v2"
)

type echoAppConfig struct {
	appName          string
	enablePrometheus bool
}

func NewEchoBuilder() *echoAppConfig {
	return &echoAppConfig{
		appName: "Barton-Echo-App",
	}
}

func (c *echoAppConfig) AppName(name string) *echoAppConfig {
	c.appName = name
	return c
}

func (c *echoAppConfig) New() (*echo.Echo, func()) {
	e := echo.New()
	wrapper := lecho.From(log.Logger)
	e.Logger = wrapper
	e.Use(lecho.Middleware(lecho.Config{Logger: wrapper}))
	e.Use(middleware.Recover())

	e.Logger.SetLevel(elog.INFO)

	p := prometheus.NewPrometheus(c.appName, nil)
	p.Use(e)
	cleanupFunc := func() {
		for _, m := range p.MetricsList {
			pg.Unregister(m.MetricCollector)
		}
	}
	return e, cleanupFunc
}
