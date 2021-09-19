package barton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/stretchr/testify/assert"
)

func formValidate(ctx context.Context, r *http.Request,
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

// TestHTTPFormAuthLoginHandler verifies authentication by posting
// HTTP form to website.
func TestHTTPFormAuthLoginHandler(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware()) // protected
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	s := NewFormAuthConfig().
		NewGuardianStrategy(formValidate)
	p := NewJWTGenPolicy(s)
	e.POST("/weblogin", c.NewEchoLoginHandler(p))

	body := strings.NewReader("username=testuser&password=testpwd")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/weblogin", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// Token is retrieved successfully.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	tokenBody := tokenBody{}
	json.Unmarshal(answer, &tokenBody)
	values := strings.Split(tokenBody.Token, ".")

	// Content of JWT meets parameters
	headerStr, err := base64.StdEncoding.DecodeString(values[0])
	assert.Nil(t, err)
	payloadStr, err := base64.StdEncoding.DecodeString(values[1])
	assert.Nil(t, err)

	header := Header{}
	payload := Payload{}

	json.Unmarshal(headerStr, &header)
	assert.Equal(t, header.Alg, "HS384")
	assert.Equal(t, header.Typ, "JWT")

	// Customized fields (user name + expire time) meets parameters.
	json.Unmarshal(payloadStr, &payload)
	assert.Equal(t, payload.Name, "testuser")
	assert.Equal(t, payload.Exp, tokenBody.Expire)

	// Received token can be used to call APIs.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v1/hello", nil)
	req.Header.Set("Authorization",
		fmt.Sprintf("Bearer %s", tokenBody.Token))

	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()

	answer, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello!", string(answer))
}

// TestHTTPFormAuthLoginHandlerCustomizedFormKey verifies authentication
// by posting HTTP form to website. It allows we specifies customized
// form field name for username and password.
func TestHTTPFormAuthLoginHandlerCustomizedFormKey(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware()) // protected
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	s := NewFormAuthConfig().UsernameKey("user").PasswordKey("pwd").
		NewGuardianStrategy(formValidate)
	p := NewJWTGenPolicy(s)
	e.POST("/weblogin", c.NewEchoLoginHandler(p))

	body := strings.NewReader("user=testuser&pwd=testpwd")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/weblogin", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// Token is retrieved successfully.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	tokenBody := tokenBody{}
	json.Unmarshal(answer, &tokenBody)
	values := strings.Split(tokenBody.Token, ".")

	// Content of JWT meets parameters
	headerStr, err := base64.StdEncoding.DecodeString(values[0])
	assert.Nil(t, err)
	payloadStr, err := base64.StdEncoding.DecodeString(values[1])
	assert.Nil(t, err)

	header := Header{}
	payload := Payload{}

	json.Unmarshal(headerStr, &header)
	assert.Equal(t, header.Alg, "HS384")
	assert.Equal(t, header.Typ, "JWT")

	// Customized fields (user name + expire time) meets parameters.
	json.Unmarshal(payloadStr, &payload)
	assert.Equal(t, payload.Name, "testuser")
	assert.Equal(t, payload.Exp, tokenBody.Expire)
}

// TestHTTPFormAuthParseFail verifies authentication failure of posting
// form will cause error returns.
func TestHTTPFormAuthParseFail(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware()) // protected
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	s := NewFormAuthConfig().
		UsernameKey("user").
		PasswordKey("pwd").
		NewGuardianStrategy(formValidate)
	p := NewJWTGenPolicy(s)
	e.POST("/weblogin", c.NewEchoLoginHandler(p))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/weblogin", nil)
	req.Header.Set("Content-Type", "badmedia;badmedia")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	_, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// Token is retrieved successfully.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestHTTPFormAuthValidateFail verifies authentication failure of posting
// form will cause error returns, when giving incorrect username and
// password.
func TestHTTPFormAuthValidateFail(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware()) // protected
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	s := NewFormAuthConfig().
		UsernameKey("user").
		PasswordKey("pwd").
		NewGuardianStrategy(formValidate)
	p := NewJWTGenPolicy(s)
	e.POST("/weblogin", c.NewEchoLoginHandler(p))

	// Intentionally provide wrong user name and password.
	body := strings.NewReader("user=testuser2&pwd=testpwd2")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/weblogin", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	_, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// Token is retrieved successfully.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestHTTPFormAuthLoginHandlerGetForm verifies authentication
// by posting HTTP form to website, when we use GET verb.
func TestHTTPFormAuthLoginHandlerGetForm(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware()) // protected
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	s := NewFormAuthConfig().UsernameKey("user").PasswordKey("pwd").
		NewGuardianStrategy(formValidate)
	p := NewJWTGenPolicy(s)
	e.GET("/weblogin", c.NewEchoLoginHandler(p))

	// It's not recommended to use GET, but we allow it to keep
	// compatibility with standard HTTP library. Note that it's
	// still not recommended due to security concern.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/weblogin?user=testuser&pwd=testpwd",
		nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// Token is retrieved successfully.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	tokenBody := tokenBody{}
	json.Unmarshal(answer, &tokenBody)
	values := strings.Split(tokenBody.Token, ".")

	// Content of JWT meets parameters
	headerStr, err := base64.StdEncoding.DecodeString(values[0])
	assert.Nil(t, err)
	payloadStr, err := base64.StdEncoding.DecodeString(values[1])
	assert.Nil(t, err)

	header := Header{}
	payload := Payload{}

	json.Unmarshal(headerStr, &header)
	assert.Equal(t, header.Alg, "HS384")
	assert.Equal(t, header.Typ, "JWT")

	// Customized fields (user name + expire time) meets parameters.
	json.Unmarshal(payloadStr, &payload)
	assert.Equal(t, payload.Name, "testuser")
	assert.Equal(t, payload.Exp, tokenBody.Expire)
}
