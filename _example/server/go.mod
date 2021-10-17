module github.com/fuzhouch/barton/_example/server

require (
	github.com/fuzhouch/barton v0.0.0
	github.com/labstack/echo/v4 v4.5.0
	github.com/shaj13/go-guardian/v2 v2.11.3
)

replace github.com/fuzhouch/barton => ../../

go 1.16
