package barton

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

// JWTGen defines interfaces that can be used to create a new token.
type JWTGen interface {
	// NewToken method returns a newly created token with claims.
	NewTokenStr(jwt.MapClaims) (string, error)
	NewEchoAuthMiddleware() echo.MiddlewareFunc
}

// TokenResponseBody represents a structure that returned JSON when
// trying to login JWT token.
type TokenResponseBody struct {
	Token  string `json:"jwt"`
	Expire int64  `json:"expire_unix_epoch"`
}
