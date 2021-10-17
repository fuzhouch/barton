package barton

import (
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
)

// JWTGenPolicy is a cofiguration we use to control how we generate JWT
// tokens. It specifies behavior such as expiration time and login
// approaches.
//
// JWTGenPolicy is designed as a separated configuration object, instead of
// being a part of HMACJWTConfig. This is to ensure we leave future
// flexibility when Barton supports JWT with public/private keys.
type JWTGenPolicy struct {
	expireSpan        time.Duration
	loginStrategy     auth.Strategy
	authFailLogMsg    string
	tokenIssuedLogMsg string
	printAuthFailLog  bool
}

// NewJWTGenPolicy generate a new policy configuration. It specifies
// behaviors like token expiration time and authentication methods. The
// policy is passed to HMACJWTConfig.NewEchoLoginHandler() method to
// generate an Echo handler function.
func NewJWTGenPolicy(strategy auth.Strategy) *JWTGenPolicy {
	return &JWTGenPolicy{
		expireSpan:        time.Hour * 1,
		loginStrategy:     strategy,
		authFailLogMsg:    "Authenticate.Fail",
		tokenIssuedLogMsg: "Authenticate.Success.JWT.Issued",
		printAuthFailLog:  false,
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

// TokenIssuedLogMsg specifies a log line string when a token is
// genearted successfully. This message is designed to use when
// developers search failure message from ElasticSearch or Splunk.
func (p *JWTGenPolicy) TokenIssuedLogMsg(msg string) *JWTGenPolicy {
	p.tokenIssuedLogMsg = msg
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
