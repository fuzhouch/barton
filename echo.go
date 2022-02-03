package barton

import (
	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	elog "github.com/labstack/gommon/log"
	pg "github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/ziflex/lecho/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// WebApp is a configuration object that sets configurations, and build
// an Echo web server via NewEcho() method.
type WebApp struct {
	appName                   string
	enablePrometheus          bool
	enableJWTAuthentication   bool
	enableOpenTelemetryTracer bool
}

// NewWebApp is main entry to start building an Echo app engine.
// It returns a chainable configuration object, WebApp, which
// is configured as setter functions. The final step is it calls New()
// function to really build an Echo engine, plus a cleanup function
// returned.
func NewWebApp(appName string) *WebApp {
	return &WebApp{
		appName:                   appName,
		enableOpenTelemetryTracer: false,
	}
}

// Name setter sets app name for Echo engine. By defualt the name is
// set to Barton-Echo-App.
func (c *WebApp) Name(name string) *WebApp {
	c.appName = name
	return c
}

// EnableOpenTelemetryTracer creates a default OpenTelemetry tracer
// middleware to all paths. It's disabled by default. Developers who
// want to customize their own OpenTelemetry tracer, can choose not to
// call this API.
//
// For security reason, this tracer does not use
func (c *WebApp) EnableOpenTelemetryTracer() *WebApp {
	c.enableOpenTelemetryTracer = true
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

	if c.enableOpenTelemetryTracer {
		log.Info().Msg("OpenTelemetryTracerMiddleware.Enabled")
		e.Use(c.openTelemetryTracerMiddleware())
	}

	cleanupFunc := func() {
		log.Info().Msg("PrometheusExporter.Cleanup")
		for _, m := range p.MetricsList {
			pg.Unregister(m.MetricCollector)
		}
		globalCleanup()
	}
	return e, cleanupFunc
}

func (wa *WebApp) openTelemetryTracerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()
			_, span := otel.Tracer(wa.appName).
				Start(ctx, c.Path())
			defer span.End()

			// For security reason, we keep only query
			// parameter and path, which are known to be
			// visible as part of public URL. Other parts,
			// actually cookie and form values, are
			// forbidden to be saved in our code.
			//
			// I can't prevent developers doing this if they
			// want to use their own tracers, though.
			span.SetAttributes(attribute.String("q",
				c.QueryString()))

			// TODO Needs a further check on semantics: What
			// if the error comes from some middleware
			// instead of real request handlers? Does it
			// cause any semantic bugs?
			err := next(c)
			if err != nil {
				// There should be no log coming out
				// here, or a bad call can cause log
				// flooding.
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			}
			return err
		}
	}
}
