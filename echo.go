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

// WebApp is a configuration object that sets configurations, and build
// an Echo web server via NewEcho() method.
type WebApp struct {
	appName                 string
	enablePrometheus        bool
	enableJWTAuthentication bool
}

// NewWebApp is main entry to start building an Echo app engine.
// It returns a chainable configuration object, WebApp, which
// is configured as setter functions. The final step is it calls New()
// function to really build an Echo engine, plus a cleanup function
// returned.
func NewWebApp(appName string) *WebApp {
	return &WebApp{appName: appName}
}

// AppName setter sets app name for Echo engine. By defualt the name is
// set to Barton-Echo-App.
func (c *WebApp) Name(name string) *WebApp {
	c.appName = name
	return c
}

// NewEcho method creates a real echo.Echo object, plus a cleanup()
// function to execute internal cleanup logic, such as
// unregistering Prometheus metrics collector in global registry.
func (c *WebApp) NewEcho() (*echo.Echo, func()) {
	e := echo.New()

	wrapper := lecho.From(log.Logger)
	e.Logger = wrapper // Echo internal log uses zerolog
	e.Use(lecho.Middleware(lecho.Config{Logger: wrapper}))
	e.Logger.SetLevel(elog.INFO)

	e.Use(middleware.Recover())

	p := prometheus.NewPrometheus(c.appName, nil)
	p.Use(e)
	log.Info().Msg("PrometheusExporter.Enabled")

	cleanupFunc := func() {
		for _, m := range p.MetricsList {
			pg.Unregister(m.MetricCollector)
		}
		globalCleanup()
	}
	return e, cleanupFunc
}
