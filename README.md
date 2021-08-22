# What is Barton?

Barton is a library written in Golang, with a set of utility functions
to help developer create a web API service in Intranet or Internet,
with a set of support features properly pre-configured. The features
include:

* Web framework, via [Echo](https://github.com/labstack/echo)
* Health monitoring, via [Prometheus](https://prometheus.io)
* Structural logs, via [Zerolog](https://github.com/rs/zerolog)
* Authentication, via [JWT](https://jwt.io)

The goal of Barton is to provide an out-of-box experience for developers,
who want to focus on their own business logic, without the needs of
spending time on library selection or configuration. For this purpose,
Barton intentionally builds itself upon a set of well known Open Source
projects, and exposes only a limited configuration options.

Barton is not designed to be a "framework" with maximized flexibility.
For example, Barton selects [Zerolog](https://github.com/rs/zerolog) as
structural log implementation, it does not offer adoptions for other 
famous logging libraries such as [Zap](https://github.com/uber-go/zap)
or [Logrus](https://github.com/sirupsen/logrus), or even standard log
module. It does not expose much options either.

I understand this may prevents some developers from using Barton in
their projects, but it keeps a minimal wrapper layer in APIs,
which leads to a clean codebase, easy to understand and optimize.
For developers who really disagree Barton's dependency selection or
configuration choice, they could fork the code and modify as they want.

## How to use Barton in your code

Barton is built with Golang 1.16 with Go module. It can be referenced
by command below.

```
go get -u https://github.com/fuzhouch/barton
```

## Quick start

The following code demonstrate how to create a simple Echo web app with
Barton APIs. You may notice Echo web app is still functioning when
the Zerolog and JWT configurations are not set. When
``NewZerologConfig`` is not called, the created Echo web app writes
structural logs to standard error. Meanwhile, JWT is not enabled until
``EnableHMACJWT()`` API is called. Unlike Zerolog and JWT, Prometheus
integration is already enabled and exposed under ``/metrics`` path.

```
import "github.com/fuzhouch/barton"

func main() {
        // Setup Zerolog
	zc := barton.NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

        // Setup JWT authentication
        testKey := []byte("keep-it-secret")
	c := barton.NewHMACJWTConfig(testKey)

        // Create Echo app with Prometheus enabled.
	// 
	e, cleanup := barton.NewWebAppBuilder("MyAPI").EnableHMACJWT(c).NewEcho()
	defer cleanup()

	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	// The logic is copied from
	// https://github.com/labstack/echo#example
	e.Logger.Fatal(e.Start(":8080"))
}
```

## Changelog

### v0.1.0

* [X] Create [Echo](https://github.com/labstack/echo) web service.
* [X] A default Prometheus exporter to export service status.
* [X] Write structural log via [Zerolog](https://github.com/rs/zerolog).
* [X] Echo app integrate with Zerolog.
* [X] Utility function to set default Zerolog global settings.
* [X] Timestamp in logs can be RFC3339 UTC or local time (with zone info).
* [X] Optionally enabled HMAC JWT token validation.
