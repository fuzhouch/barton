package barton

import (
	"context"
	"net/http"

	a "github.com/shaj13/go-guardian/v2/auth"
	b "github.com/shaj13/go-guardian/v2/auth/strategies/basic"
)

// formAuth defines a go-guardian strategy, accepting HTTP form
// authentication.
type formAuth struct {
	fn     b.AuthenticateFunc
	parser func(r *http.Request) (string, string, error)
}

// FormAuth creates a cofig object to configure authentication
// strategy.
type FormAuth struct {
	usernameFormKey string
	passwordFormKey string
}

// NewFormAuth creates an object that configures form authentication.
func NewFormAuth() *FormAuth {
	return &FormAuth{
		usernameFormKey: "username",
		passwordFormKey: "password",
	}
}

// UsernameKey is control option for NewGuardianFormAuthStrategy()
// creator, to specify form key name for retriving username.
func (c *FormAuth) UsernameKey(key string) *FormAuth {
	c.usernameFormKey = key
	return c
}

// PasswordKey is control option for NewGuardianFormAuthStrategy()
// creator, to specify form key name for retriving password.
func (c *FormAuth) PasswordKey(key string) *FormAuth {
	c.passwordFormKey = key
	return c
}

// NewGuardianStrategy method provides a go-guardian to accept username
// and password from HTTP form body, uesful for web page authentication.
// The returned strategy does not support go-guardian's cache strategy
// for now. As an alternative solution, manipulate cache in
// basic.AuthenticateFunc.
func (c *FormAuth) NewGuardianStrategy(fn b.AuthenticateFunc) a.Strategy {
	strategy := formAuth{
		fn:     fn,
		parser: nil,
	}

	strategy.parser = func(r *http.Request) (string, string, error) {
		err := r.ParseForm()
		if err != nil {
			// XXX Never write any log here. We delegate to
			// NewEchoLoginHandler() to decide
			// authentication error logging and counter
			// behavior.
			return "", "", err
		}

		username := r.Form.Get(c.usernameFormKey)
		password := r.Form.Get(c.passwordFormKey)
		return username, password, nil
	}
	return strategy
}

// Authenticate implements go-guardian's auth.Strategy interface. So it
// can be called just like other go-guardian interfaces.
func (f formAuth) Authenticate(ctx context.Context, r *http.Request) (a.Info, error) {
	user, pass, err := f.parser(r)
	if err != nil {
		// Same here. Don't write any logs here. We don't want
		// to flood our log storage.
		return nil, err
	}
	return f.fn(ctx, r, user, pass)
}
