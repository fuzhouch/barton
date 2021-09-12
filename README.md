# What is Barton?

Barton is a library written in Golang, with a set of utility functions
to help developer create a web API service in Intranet or Internet,
with a set of support features properly pre-configured. The features
include:

* Web framework, via [Echo](https://github.com/labstack/echo)
* Health monitoring, via [Prometheus](https://prometheus.io)
* Structural logs, via [Zerolog](https://github.com/rs/zerolog)
* Token access, via [JWT](https://jwt.io)
* Authentication, via [go-guardian](https://github.com/shaj13/go-guardian)

The goal of Barton is to provide an "battery included" tool for developers,
who want to focus on their own business logic, without the needs of
spending time on library exploration or customization. To meet this
goal, Barton intentionally builds itself upon a set of well known Open
Source projects, and exposes only a limited configuration options.

Barton is not designed to be a "framework" with maximized flexibility.
For example, Barton selects [Zerolog](https://github.com/rs/zerolog) as
structural logging infrastructure. It does not offer any adoption layer
for other famous logging libraries such as
[Zap](https://github.com/uber-go/zap) or
[Logrus](https://github.com/sirupsen/logrus), or even standard log
module. It also pre-configures options for
[Zerolog](https://github.com/rs/zerolog), which forces always writting
INFO leve logs no matter under development mode or production.

This design decision is not a preferred way for some developers, who
want to adopt their favorite libraries as much as possible. Barton
chooses an carefully chosen set of dependencies, which keep a minimal
warpper layer and a clean codebase. I believe it makes Barton code easy
to understand and optimize. For developers who really disagree Barton's
dependency selection or design choice, just go ahead to fork the code
and modify as you wish.

## How to use Barton

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
$ go mod init github.com/fuzhouch/test
$ go get -u github.com/fuzhouch/barton@v0.1.0
$ go get -u github.com/labstack/echo/v4@v4.3.0
$ vim main.go
```

```go
// File - main.go
package main

import (
	"net/http"

	"github.com/fuzhouch/barton"
	"github.com/labstack/echo/v4"
)

func main() {
	// Setup Zerolog
	zc := barton.NewZerologConfig().UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	// Setup JWT authentication
	testKey := []byte("keep-it-secret")
	c := barton.NewHMACJWTConfig(testKey)

	// Create Echo app with Prometheus enabled.
	// JWT token authentication is enabled explicitly.
	e, cleanup := barton.NewWebAppBuilder("MyAPI").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoMiddleware()) // API /test is under protection.

	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	// The logic is copied from
	// https://github.com/labstack/echo#example
	e.Logger.Fatal(e.Start(":8080"))
}
```

## Changelog

### v0.2.0

* [X] A login handler based on https://github.com/shaj13/go-guardian.
* [X] Support basic-auth login. See UT as demonstration.
* [ ] Support form-based login. Provide a go-guardian's Strategy interface.
* [X] Customizable log-line on JWT generation and authentication failure.
* [X] Prometheus counter for JWT generation and authentication failure.
* [ ] A login command line handler based on https://github.com/spf13/cobra.

### v0.1.0

* [X] Create [Echo](https://github.com/labstack/echo) web service.
* [X] A default Prometheus exporter to export service status.
* [X] Write structural log via [Zerolog](https://github.com/rs/zerolog).
* [X] Echo app integrate with Zerolog.
* [X] Utility function to set default Zerolog global settings.
* [X] Timestamp in logs can be RFC3339 UTC or local time (with zone info).
* [X] Optionally enabled HMAC JWT token validation.
