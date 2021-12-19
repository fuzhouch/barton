package barton

import (
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// ErrUserContextParseFail is triggerred when JWT context fail to parse.
var ErrUserContextParseFail = errors.New("UserContextParseFail")

// HMACJWTGen provides JWT generation logic with symmetric
// encryption. By default it supports HS256, HS384 and HS512.
type HMACJWTGen struct {
	signingMethod string
	// TODO Let's double think about this: I lost type safety but
	// gain ability to test a failed case in UT. Is it a good
	// choice. (see unit test: TestEchoJWTGenFailure)
	signingKey interface{}
}

// NewHMACJWTGen creates a new configuration object to generate JWT
// token handler and middleware.
func NewHMACJWTGen(signingKey []byte) *HMACJWTGen {
	return &HMACJWTGen{
		signingMethod: "HS256",
		signingKey:    signingKey,
	}
}

// SigningKey specifies signing key for JWT signing. The given secret
// should not be shared with anyone.
func (hc *HMACJWTGen) SigningKey(secret []byte) *HMACJWTGen {
	hc.signingKey = secret
	return hc
}

// SigningMethod specifies signing method. Supposed method is HS256,
// HS384 and HS512.
func (hc *HMACJWTGen) SigningMethod(method string) *HMACJWTGen {
	hc.signingMethod = method
	return hc
}

// NewEchoAuthMiddleware returns a token validation middleware for
// Labstack Echo framework.
func (hc *HMACJWTGen) NewEchoAuthMiddleware() echo.MiddlewareFunc {
	config := middleware.JWTConfig{
		TokenLookup:   "header:Authorization",
		AuthScheme:    "Bearer",
		SigningMethod: hc.signingMethod,
		SigningKey:    hc.signingKey,
		// TODO By reading JWT Library code I see a lot of
		// reflection-based method to parse token. Not sure
		// whether it will be be a bottleneck. Will do
		// experiment in future.
	}
	return middleware.JWTWithConfig(config)
}

// NewToken method returns a new token with claims in parameters. It
// returns a encoded string of JWT token.
func (hc *HMACJWTGen) NewTokenStr(claims jwt.MapClaims) (string, error) {
	alg := jwt.GetSigningMethod(hc.signingMethod)
	token := jwt.NewWithClaims(alg, claims)
	tokenStr, err := token.SignedString(hc.signingKey)
	return tokenStr, err
}
