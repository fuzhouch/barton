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

	gen := barton.NewHMACJWTGen(testKey)
	// Authentication method
	strategy := basic.New(validate)
	b := barton.NewJWTBuilder(strategy, gen).PrintAuthFailLog(true)

	// Create Echo app with Prometheus enabled.
	// JWT token authentication is enabled explicitly.
	e, cleanup := barton.NewWebApp("MyAPI").NewEcho()
	defer cleanup()

	// Add /login endpoint to handle login requests. It's
	// unprotected.
	e.POST("/login", b.NewEchoLoginHandler())

	// All other APIs, are protected by JWT checking middleware.
	g := e.Group("/v1", b.NewEchoAuthMiddleware())
	g.GET("/hello", func(c echo.Context) error { // Protected by JWT.
		return c.String(http.StatusOK, "hello!")
	})

	// The logic is copied from
	// https://github.com/labstack/echo#example
	e.Logger.Fatal(e.Start(":8080"))
}
