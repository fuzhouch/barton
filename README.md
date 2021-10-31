[![codecov](https://codecov.io/gh/fuzhouch/barton/branch/main/graph/badge.svg?token=Z6F4LP1L1O)](https://codecov.io/gh/fuzhouch/barton)

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

Let's start from a complete example by building a web service and a
client which can talk to each other.

The web server listens ``http://127.0.0.1:8080`` and provides two
endpoints. The first endpoint, ``/login`` to take an HTTP basic login
request, and then return an JWT token. The second endpoint,
``/v1/hello``, is protected by JWT authentication, accepts only request
with a valid JWT token attached in HTTP request. If the token is good,
it returns a string "hello!". If the token is invalid or expired, it
returns an error message with HTTP status code set to 400.

The following code demonstrate how to create a simple Echo web app with
Barton APIs. You may notice Echo web app is still functioning when
the Zerolog and JWT configurations are not set. When
``NewZerologConfig`` is not called, the created Echo web app writes
structural logs to standard error. Note that Prometheus
integration is already enabled and exposed under ``/metrics`` path.

The full code source and project files are available at ``_example/``
folder under https://github.com/fuzhouch/barton project.

```go
// _example/server/main.go
package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/fuzhouch/barton"
	"github.com/labstack/echo/v4"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
)

func validate(ctx context.Context, r *http.Request,
	userName, password string) (auth.Info, error) {

	// here connect to db or any other service to fetch user and validate it.
	if userName == "testuser" && password == "testpwd" {
		return auth.NewDefaultUser("testuser",
			"testpwd",
			nil,
			nil), nil
	}
	return nil, fmt.Errorf("Invalid credentials")
}

func main() {
	// Setup Zerolog
	zc := barton.NewZerologConfig().UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	// Setup JWT authentication
	testKey := []byte("keep-it-secret")

	jwtGen := barton.NewHMACJWTGen(testKey)
	// Authentication method
	strategy := basic.New(validate)
	policy := barton.NewJWTGenPolicy(strategy).PrintAuthFailLog(true)

	// Create Echo app with Prometheus enabled.
	// JWT token authentication is enabled explicitly.
	e, cleanup := barton.NewWebApp("MyAPI").NewEcho()
	defer cleanup()

	// Add /login endpoint to handle login requests. It's
	// unprotected.
	e.POST("/login", jwtGen.NewEchoLoginHandler(policy))

	// All other APIs, are protected by JWT checking middleware.
	g := e.Group("/v1", jwtGen.NewEchoMiddleware())
	g.GET("/hello", func(c echo.Context) error { // Protected by JWT.
		return c.String(http.StatusOK, "hello!")
	})

	// The logic is copied from
	// https://github.com/labstack/echo#example
	e.Logger.Fatal(e.Start(":8080"))
}
```

Starting from Barton ``v0.3.0``, a sub-module called ``cli`` is
introduced to support creation of command line client. It provides a
``RootCLI`` and an ``HTTPBasicLogin`` to create
[Cobra](https://github.com/spf13/cobra) based command line processor.
The ``HTTPBasicLogin`` provides subcommand to authenticate with remote
server, and save received JWT token in configuration file. A full client
code looks like below:

```go
// _example/client/main.go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/fuzhouch/barton"
	"github.com/fuzhouch/barton/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	// Setup Zerolog
	zc := barton.NewZerologConfig().UseUTCTime()
	zc.SetGlobalPolicy().SetOffGlobalLogger()

	login := cli.NewHTTPBasicLogin("login", "http://127.0.0.1:8080/login")

	rootCLI, cleanup := cli.NewRootCLI("testcli").
		SetLocalViperPolicy().
		AddSubcommand(login).
		NewCobraE(func(c *cobra.Command, args []string) error {
			// IMPORTANT This is an example to show usage of Barton
			// APIs. For showing the main path it skips all error
			// handling logic. This is bad practice for production
			// use. Please properly handle errors instead of copy
			// and paste code blindly.
			token := viper.GetString("testcli.login.token")
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/v1/hello", nil)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			cli := &http.Client{}
			resp, _ := cli.Do(req)
			defer resp.Body.Close()

			answer, _ := ioutil.ReadAll(resp.Body)
			fmt.Printf("Answer from server: %s\n", answer)

			return nil
		})
	defer cleanup()

	err := rootCLI.Execute()
	if err != nil {
		fmt.Printf("Error on execution: %s.", err.Error())
		os.Exit(1)
	}
}
```

Please check unit test code to get detailed explanation of APIs and
features.

## Changelog

### v0.4.0 (developing)

* [ ] Bind environment variable on root and subcommand.
* [X] Configuration option to skip reading configuration files.
* [ ] Server-end send telemetry via OpenTelemetry API.
* [X] RootCLI uses Flags() to allow subcommands use same shortcut names.

### v0.3.1

* [X] Fix unit test coverage drop shown only on codecov.io.

### v0.3.0

* [X] Default login sub-command based on github.com/spf13/cobra
* [X] Username/password basic HTTP login as command line options.
* [X] URL as command line options.
* [X] Subcommands support configuration file, following XDG.
* [X] Default username/token configuration section in configuration file.
* [X] Built-in login subcommand to send request and receive token.
* [X] Type renaming to remove golint errors.

### v0.2.0

* [X] A login handler based on https://github.com/shaj13/go-guardian.
* [X] Support basic-auth login. See UT as demonstration.
* [X] Support form-based login. Provide a go-guardian's Strategy interface.
* [X] Customizable log-line on JWT generation and authentication failure.
* [X] Prometheus counter for JWT generation and authentication failure.

### v0.1.0

* [X] Create [Echo](https://github.com/labstack/echo) web service.
* [X] A default Prometheus exporter to export service status.
* [X] Write structural log via [Zerolog](https://github.com/rs/zerolog).
* [X] Echo app integrate with Zerolog.
* [X] Utility function to set default Zerolog global settings.
* [X] Timestamp in logs can be RFC3339 UTC or local time (with zone info).
* [X] Optionally enabled HMAC JWT token validation.
