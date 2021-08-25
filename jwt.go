package barton

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// HMACJWTConfig provides symmetric encryption support. By default it
// supports HS256, HS384 and HS512.
type HMACJWTConfig struct {
	signingMethod string
	signingKey    []byte
}

func NewHMACJWTConfig(signingKey []byte) *HMACJWTConfig {
	return &HMACJWTConfig{
		signingMethod: "HS256",
		signingKey:    signingKey,
	}
}

func (c *HMACJWTConfig) SigningKey(secret []byte) *HMACJWTConfig {
	c.signingKey = secret
	return c
}

func (c *HMACJWTConfig) SigningMethod(method string) *HMACJWTConfig {
	c.signingMethod = method
	return c
}

func (c *HMACJWTConfig) NewEchoMiddleware() echo.MiddlewareFunc {
	config := middleware.JWTConfig{
		TokenLookup:   "header:Authorization",
		AuthScheme:    "Bearer",
		SigningMethod: c.signingMethod,
		SigningKey:    c.signingKey,
		// TODO By reading JWT Library code I see a lot of
		// reflection-based method to parse token. Not sure
		// whether it will be be a bottleneck. Will do
		// experiment in future.
	}
	return middleware.JWTWithConfig(config)
}
