package barton

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
)

// ErrContextParseFail is triggerred when JWT context fail to parse.
var ErrContextParseFail = errors.New("UserContextParseFail")

// HMACJWTGen provides JWT generation logic with symmetric
// encryption. By default it supports HS256, HS384 and HS512.
type HMACJWTGen struct {
	signingMethod string
	// TODO Let's double think about this: I lost type safety but
	// gain ability to test a failed case in UT. Is it a good
	// choice. (see unit test: TestEchoJWTGenFailure)
	signingKey     interface{}
	contextKey     string
	usernameJWTKey string
}

// NewHMACJWTGen creates a new configuration object to generate JWT
// token handler and middleware.
func NewHMACJWTGen(signingKey []byte) *HMACJWTGen {
	return &HMACJWTGen{
		signingMethod:  "HS256",
		signingKey:     signingKey,
		contextKey:     "user", // Compatible with Echo
		usernameJWTKey: "name",
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

// ContextKey specifies the key name we use to lookup token object in
// echo's Context object.
func (hc *HMACJWTGen) ContextKey(keyName string) *HMACJWTGen {
	hc.contextKey = keyName
	return hc
}

// NewEchoMiddleware returns a token validation middleware for Labstack
// Echo framework.
func (hc *HMACJWTGen) NewEchoMiddleware() echo.MiddlewareFunc {
	config := middleware.JWTConfig{
		TokenLookup:   "header:Authorization",
		AuthScheme:    "Bearer",
		SigningMethod: hc.signingMethod,
		SigningKey:    hc.signingKey,
		ContextKey:    hc.contextKey,
		// TODO By reading JWT Library code I see a lot of
		// reflection-based method to parse token. Not sure
		// whether it will be be a bottleneck. Will do
		// experiment in future.
	}
	return middleware.JWTWithConfig(config)
}

// NewEchoLogRequestMiddleware is a middleware to log request URL and
// user name. Useful for audit purpose. Note that this middleware still
// prints when there's no token accessed
func (hc *HMACJWTGen) NewEchoLogRequestMiddleware(p *JWTGenPolicy) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := c.Get(hc.contextKey)
			if key == nil {
				log.Info().
					Bool("auth", false).
					Str("scheme", c.Scheme()).
					Str("request", c.Path()).
					Str("querystr", c.QueryString()).
					Msg(p.requestLogMsg)
				return next(c)
			}

			var user string
			if token, ok := key.(*jwt.Token); ok {
				cl := token.Claims.(jwt.MapClaims)
				user = cl[hc.usernameJWTKey].(string)
				log.Info().
					Bool("auth", true).
					Str(hc.contextKey, user).
					Str("scheme", c.Scheme()).
					Str("request", c.Path()).
					Str("querystr", c.QueryString()).
					Msg(p.requestLogMsg)
			} else {
				// Something wrong happening: context
				// key is found, but somehow token
				// object was not parsed as jwt.Token.
				// It may happen when upgrading JWT
				// token dependencies, while JWT tokens
				// are not matched.
				log.Error().
					Err(ErrContextParseFail).
					Str(hc.contextKey, user).
					Bool("auth", true).
					Str("scheme", c.Scheme()).
					Str("request", c.Path()).
					Str("querystr", c.QueryString()).
					Msg(p.requestLogMsg)
			}
			return next(c)
		}
	}
}

// A private function to generate JWT token from given user name.
func (hc *HMACJWTGen) token(exp int64, name string) (string, error) {
	alg := jwt.GetSigningMethod(hc.signingMethod)
	claims := jwt.MapClaims{
		"exp":             exp,
		hc.usernameJWTKey: name,
	}
	token := jwt.NewWithClaims(alg, claims)
	tokenStr, err := token.SignedString(hc.signingKey)
	return tokenStr, err
}

// TokenResponseBody represents a structure that returned JSON when
// trying to login JWT token.
type TokenResponseBody struct {
	Token  string `json:"jwt"`
	Expire int64  `json:"expire_unix_epoch"`
}

// NewEchoLoginHandler create an Labstack Echo framework handler. It
// takes parameter p, an JWT generator policy object, and a
// handlerIdentifier string to distinguish this handler when creating
// Prometheus counters.
func (hc *HMACJWTGen) NewEchoLoginHandler(p *JWTGenPolicy,
	handlerIdentifier ...string) echo.HandlerFunc {

	effectivePrefix := ""
	if len(handlerIdentifier) > 1 {
		effectivePrefix = handlerIdentifier[0]
		log.Warn().
			Str("Prefix", effectivePrefix).
			Msg("HandlerIdentifier.TakeFirstOne")
	} else if len(handlerIdentifier) == 1 {
		effectivePrefix = handlerIdentifier[0]
	} else if len(handlerIdentifier) == 0 {
		effectivePrefix = "Barton"
	}

	// Register Prometheus counters
	m := registerLoginMetrics(effectivePrefix)

	return func(c echo.Context) error {
		r := c.Request()
		user, err := p.loginStrategy.Authenticate(r.Context(), r)
		if err != nil {
			// The log is not printed by default, with
			// purpose that we intentinally avoid log
			// flooding when a bad guy generates huge number
			// of traffic. However, counter is always
			// increasing.
			m.jwtFailedAuthCount.Inc()
			if p.printAuthFailLog {
				log.Error().
					Err(err).
					Msg(p.authFailLogMsg)
			}
			return c.String(http.StatusUnauthorized,
				"{\"msg\":\"Bad username or password\"}")
		}

		username := user.GetUserName()
		expireTime := time.Now().Add(p.expireSpan).Unix()
		tokenStr, err := hc.token(expireTime, username)
		if err != nil {
			m.jwtInternalErrorCount.Inc()
			log.Error().Err(err).Msg("Sign.JWT.Token.Fail")
			return c.String(http.StatusInternalServerError,
				"{\"msg\":\"Failed to generate JWT token\"}")
		}

		m.jwtIssuedCount.Inc()
		log.Info().
			Str("name", username).
			Int64("exp", expireTime).
			Msg(p.tokenIssuedLogMsg)
		t := TokenResponseBody{
			Token:  tokenStr,
			Expire: expireTime,
		}
		return c.JSON(http.StatusOK, t)
	}
}
