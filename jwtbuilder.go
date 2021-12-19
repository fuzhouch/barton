package barton

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
	"github.com/shaj13/go-guardian/v2/auth"
)

// JWTBuilder is a cofiguration we use to control how we generate JWT
// tokens. It specifies behavior such as expiration time and login
// approaches.
//
// JWTBuilder is designed as a separated configuration object, instead of
// being a part of HMACJWTConfig. This is to ensure we leave future
// flexibility when Barton supports JWT with public/private keys.
type JWTBuilder struct {
	expireSpan        time.Duration
	loginStrategy     auth.Strategy
	authFailLogMsg    string
	tokenIssuedLogMsg string
	requestLogMsg     string
	printAuthFailLog  bool
	usernameJWTKey    string
	tokenKeyInContext string
	gen               JWTGen
}

// NewJWTBuilder creates an object to generate Echo middleware and
// handlers for JWT creation.
func NewJWTBuilder(strategy auth.Strategy, g JWTGen) *JWTBuilder {
	return &JWTBuilder{
		expireSpan:        time.Hour * 1,
		loginStrategy:     strategy,
		authFailLogMsg:    "Authenticate.Fail",
		tokenIssuedLogMsg: "Authenticate.Success.JWT.Issued",
		requestLogMsg:     "IncomingRequest",
		printAuthFailLog:  false,
		usernameJWTKey:    "name", // Compatible with JWT standard
		tokenKeyInContext: middleware.DefaultJWTConfig.ContextKey,
		gen:               g,
	}
	// NOTE Customization of tokenKeyInContext should be avoided as
	// it does not introduce any flexibility but only add confusion.
	// Just set it same with default values.
}

// ExpireSpan specifies a expire time duration.
func (p *JWTBuilder) ExpireSpan(expire time.Duration) *JWTBuilder {
	p.expireSpan = expire
	return p
}

// AuthFailLogMsg specifies a log line string when authentication
// check fails. This message is designed to allow developers search
// failure message from ElasticSearch or Splunk with customized messge.
func (p *JWTBuilder) AuthFailLogMsg(msg string) *JWTBuilder {
	p.authFailLogMsg = msg
	return p
}

// TokenIssuedLogMsg specifies a log line string when a token is
// genearted successfully. This message is designed to allow
// developers search failure message from ElasticSearch or Splunk
// with customized messge.
func (p *JWTBuilder) TokenIssuedLogMsg(msg string) *JWTBuilder {
	p.tokenIssuedLogMsg = msg
	return p
}

// RequestLogMsg specifies a log ling string used by HMACJWTConfig,
// which is printed when using LogRequest middleware The message is
// designed to allow developers search failure message from
// ElasticSearch or Splunk with customized messge.
func (p *JWTBuilder) RequestLogMsg(msg string) *JWTBuilder {
	p.requestLogMsg = msg
	return p
}

// PrintAuthFailLog specifies whether login handler writes log line on
// a failed authentication step. By default it's set to false.
// Although log line is useful for debugging, it can cause log flooding
// and eat up disk space of log server, when a malform client
// intentially generate many bad requests. This is especially true
// in a cost sensitive deployment.
//
// It's recommended to enable PrintAuthFailLog in development mode, then
// disable it in production mode.
func (p *JWTBuilder) PrintAuthFailLog(enable bool) *JWTBuilder {
	p.printAuthFailLog = enable
	return p
}

// NewEchoAuthMiddleware returns a new Echo middleware which handles
// JWT authentication.
func (p *JWTBuilder) NewEchoAuthMiddleware() echo.MiddlewareFunc {
	return p.gen.NewEchoAuthMiddleware()
}

// NewEchoLogRequestMiddleware is a middleware to log request URL and
// user name. Useful for audit purpose. Note that this middleware still
// prints when there's no token accessed
func (p *JWTBuilder) NewEchoLogRequestMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := c.Get(p.tokenKeyInContext)
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
				user = cl[p.usernameJWTKey].(string)
				log.Info().
					Bool("auth", true).
					Str(p.tokenKeyInContext, user).
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
					Err(ErrUserContextParseFail).
					Str(p.tokenKeyInContext, user).
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

// NewEchoLoginHandler create an Labstack Echo framework handler. It
// takes parameter p, an JWT generator policy object, and a
// identifier string to distinguish this handler when creating
// Prometheus counters.
func (p *JWTBuilder) NewEchoLoginHandler(identifier ...string) echo.HandlerFunc {
	effectivePrefix := ""
	if len(identifier) > 1 {
		effectivePrefix = identifier[0]
		log.Warn().
			Str("Prefix", effectivePrefix).
			Msg("HandlerIdentifier.TakeFirstOne")
	} else if len(identifier) == 1 {
		effectivePrefix = identifier[0]
	} else if len(identifier) == 0 {
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
		tokenStr, err := p.gen.NewTokenStr(jwt.MapClaims{
			"exp":            expireTime,
			p.usernameJWTKey: username,
		})
		if err != nil {
			m.jwtInternalErrorCount.Inc()
			log.Error().Err(err).Msg("Sign.JWT.Token.Fail")
			return c.String(http.StatusInternalServerError,
				"{\"msg\":\"Failed to generate JWT token\"}")
		}

		m.jwtIssuedCount.Inc()
		log.Info().
			Str(p.usernameJWTKey, username).
			Int64("exp", expireTime).
			Msg(p.tokenIssuedLogMsg)
		t := TokenResponseBody{
			Token:  tokenStr,
			Expire: expireTime,
		}
		return c.JSON(http.StatusOK, t)
	}
}
