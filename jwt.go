package barton

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/shaj13/go-guardian/v2/auth"
)

// HMACJWTConfig provides symmetric encryption support. By default it
// supports HS256, HS384 and HS512.
type HMACJWTConfig struct {
	signingMethod string
	// TODO Let's double think about this: I lost type safety but
	// gain ability to test a failed case in UT. Is it a good
	// choice. (see unit test: TestEchoJWTGenFailure)
	signingKey interface{}
	contextKey string
}

// NewHMACJWTConfig creates a new configuration object to generate JWT
// token handler and middleware.
func NewHMACJWTConfig(signingKey []byte) *HMACJWTConfig {
	return &HMACJWTConfig{
		signingMethod: "HS256",
		signingKey:    signingKey,
		contextKey:    "user", // Keep compatibility with Echo.
	}
}

// SigningKey specifies signing key for JWT signing. The given secret
// should not be shared with anyone.
func (c *HMACJWTConfig) SigningKey(secret []byte) *HMACJWTConfig {
	c.signingKey = secret
	return c
}

// SigningMethod specifies signing method. Supposed method is HS256,
// HS384 and HS512.
func (c *HMACJWTConfig) SigningMethod(method string) *HMACJWTConfig {
	c.signingMethod = method
	return c
}

// ContextKey specifies the key name we use to lookup token object in
// echo's Context object.
func (c *HMACJWTConfig) ContextKey(keyName string) *HMACJWTConfig {
	c.contextKey = keyName
	return c
}

// NewEchoMiddleware returns a token validation middleware for Labstack
// Echo framework.
func (c *HMACJWTConfig) NewEchoMiddleware() echo.MiddlewareFunc {
	config := middleware.JWTConfig{
		TokenLookup:   "header:Authorization",
		AuthScheme:    "Bearer",
		SigningMethod: c.signingMethod,
		SigningKey:    c.signingKey,
		ContextKey:    c.contextKey,
		// TODO By reading JWT Library code I see a lot of
		// reflection-based method to parse token. Not sure
		// whether it will be be a bottleneck. Will do
		// experiment in future.
	}
	return middleware.JWTWithConfig(config)
}

// JWTGenPolicy is a cofiguration we use to control how we generate JWT
// tokens. It specifies behavior such as expiration time and login
// approaches.
//
// JWTGenPolicy is designed as a separated configuration object, instead of
// being a part of HMACJWTConfig. This is to ensure we leave future
// flexibility when Barton supports JWT with public/private keys.
type JWTGenPolicy struct {
	expireSpan         time.Duration
	loginStrategy      auth.Strategy
	authFailLogMsg     string
	tokenGrantedLogMsg string
	printAuthFailLog   bool
}

// NewJWTGenPolicy generate a new policy configuration. It specifies
// behaviors like token expiration time and authentication methods. The
// policy is passed to HMACJWTConfig.NewEchoLoginHandler() method to
// generate an Echo handler function.
func NewJWTGenPolicy(strategy auth.Strategy) *JWTGenPolicy {
	return &JWTGenPolicy{
		expireSpan:         time.Hour * 1,
		loginStrategy:      strategy,
		authFailLogMsg:     "Authenticate.Fail",
		tokenGrantedLogMsg: "Authenticate.Success.JWT.Granted",
		printAuthFailLog:   false,
	}
}

// ExpireSpan specifies a expire time duration.
func (p *JWTGenPolicy) ExpireSpan(expire time.Duration) *JWTGenPolicy {
	p.expireSpan = expire
	return p
}

// AuthFailLogMsg specifies a log line string when authentication
// check fails. This message is designed to use when developers search
// failure message from ElasticSearch or Splunk.
func (p *JWTGenPolicy) AuthFailLogMsg(msg string) *JWTGenPolicy {
	p.authFailLogMsg = msg
	return p
}

// TokenGrantedLogMsg specifies a log line string when a token is
// genearted successfully. This message is designed to use when
// developers search failure message from ElasticSearch or Splunk.
func (p *JWTGenPolicy) TokenGrantedLogMsg(msg string) *JWTGenPolicy {
	p.tokenGrantedLogMsg = msg
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
func (p *JWTGenPolicy) PrintAuthFailLog(enable bool) *JWTGenPolicy {
	p.printAuthFailLog = enable
	return p
}

// A private function to generate JWT token from given user name.
func (c *HMACJWTConfig) token(exp int64, name string) (string, error) {
	alg := jwt.GetSigningMethod(c.signingMethod)
	claims := jwt.MapClaims{
		"exp":  exp,
		"name": name,
	}
	token := jwt.NewWithClaims(alg, claims)
	tokenStr, err := token.SignedString(c.signingKey)
	return tokenStr, err
}

type tokenBody struct {
	Token  string `json:"jwt"`
	Expire int64  `json:"expire_unix_epoch"`
}
