package barton

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
	"github.com/stretchr/testify/assert"
)

func newExpiredToken(t *testing.T, method string, key []byte) string {
	alg := jwt.GetSigningMethod(method)
	assert.NotNil(t, alg)

	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Minute * -10).Unix(),
	}
	token := jwt.NewWithClaims(alg, claims)
	tokenStr, _ := token.SignedString(key)
	return tokenStr
}

func newToken(t *testing.T, method string, key []byte) string {
	alg := jwt.GetSigningMethod(method)
	assert.NotNil(t, alg)
	token := jwt.New(alg)
	tokenStr, _ := token.SignedString(key)
	return tokenStr
}

func TestHMACJWTDefaultSetting(t *testing.T) {
	testKey := "test123"
	c := NewHMACJWTConfig([]byte(testKey))
	assert.Equal(t, c.signingMethod, "HS256")
	if signingKeyBytes, ok := c.signingKey.([]byte); ok {
		assert.Equal(t, string(signingKeyBytes), testKey)
	} else {
		t.Fatal("SigningKeyConversionFail.test123")
	}

	testKey2 := "test456"
	c.SigningKey([]byte(testKey2)).SigningMethod("HS384")
	assert.Equal(t, c.signingMethod, "HS384")
	if signingKeyBytes, ok := c.signingKey.([]byte); ok {
		assert.Equal(t, string(signingKeyBytes), testKey2)
	} else {
		t.Fatal("SigningKeyConversionFail.test456")
	}
}

func TestEchoEnableJWTPreventNoJWTAccess(t *testing.T) {
	testKey := "test123"
	c := NewHMACJWTConfig([]byte(testKey))

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoMiddleware())

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/nojwt", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEchoEnableJWTPreventInvalidJWTAccess(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey)

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoMiddleware())

	badSignKey := []byte("test456")
	badSignKeyToken := newToken(t, "HS256", badSignKey)
	expiredToken := newExpiredToken(t, "HS256", testKey)
	unmatchedToken1 := newToken(t, "HS384", testKey)
	unmatchedToken2 := newToken(t, "HS512", testKey)

	badTokens := []string{
		badSignKeyToken,
		expiredToken,
		unmatchedToken1,
		unmatchedToken2,
	}

	for _, eachToken := range badTokens {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test/badjwt", nil)
		req.Header.Set("Authorization",
			fmt.Sprintf("Bearer %s", eachToken))
		e.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestEchoEnableJWTAllowValidToken(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	e.Use(c.NewEchoMiddleware())
	defer cleanup()

	e.GET("/test/jwt", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	validToken := newToken(t, "HS384", testKey)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/jwt", nil)
	req.Header.Set("Authorization",
		fmt.Sprintf("Bearer %s", validToken))
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello!", string(answer))
}

func validate(ctx context.Context, r *http.Request,
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

func newBasicAuthPolicy() *JWTGenPolicy {
	cache := libcache.FIFO.New(0)
	cache.SetTTL(time.Minute * 5)
	cache.RegisterOnExpired(func(key, _ interface{}) {
		cache.Peek(key)
	})
	strategy := basic.NewCached(validate, cache)
	return NewJWTPolicy(strategy)
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload struct {
	Name string `json:"name"`
	Exp  int64  `json:"exp"`
}

type Message struct {
	Msg string `json:"msg"`
}

func TestEchoReturnJWTToken(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	p := newBasicAuthPolicy()
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Let's get token first.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// JWT token is successfully returned
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

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(),
		"Authenticate.Success.JWT.Granted"))
	assert.True(t, strings.Contains(buf.String(),
		"\"name\":\"testuser\""))

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

func TestEchoReturnJWTTokenCustomizedLogs(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy().TokenGrantedLogMsg("Bravo!")
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Let's get token first.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// JWT token is successfully returned
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

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(), "Bravo!"))
	assert.True(t, strings.Contains(buf.String(),
		"\"name\":\"testuser\""))
}

func TestEchoBadAuthenticationNoLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS256")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy()
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Intentionally try to login with a bad password
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:badpassword")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	msg := Message{}
	json.Unmarshal(answer, &msg)
	assert.Equal(t, "Bad username or password", msg.Msg)

	// Log is printed to support ElasticSearch query
	assert.False(t, strings.Contains(buf.String(),
		"Authenticate.Fail"))
}

func TestEchoBadAuthenticationPrintLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS256")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy().PrintAuthFailLog(true)
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Intentionally try to login with a bad password
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:badpassword")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	msg := Message{}
	json.Unmarshal(answer, &msg)
	assert.Equal(t, "Bad username or password", msg.Msg)

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(),
		"Authenticate.Fail"))
}

func TestEchoBadAuthenticationPrintCustomizedLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS256")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy().
		AuthFailLogMsg("Don't Panic!").
		PrintAuthFailLog(true)
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Intentionally try to login with a bad password
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:badpassword")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	msg := Message{}
	json.Unmarshal(answer, &msg)
	assert.Equal(t, "Bad username or password", msg.Msg)

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(), "Don't Panic!"))
}

func TestEchoReturnJWTTokenWithShorterExpireSpan(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTConfig(testKey).SigningMethod("HS384")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	// Always return expired token
	p := newBasicAuthPolicy().ExpireSpan(time.Hour * -1)
	e.POST("/login", c.NewEchoLoginHandler(p))

	// Let's get token first.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	// JWT token is successfully returned
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

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(),
		"Authenticate.Success.JWT.Granted"))
	assert.True(t, strings.Contains(buf.String(),
		"\"name\":\"testuser\""))

	// However, the login always fails because retrieved token
	// is expired.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v1/hello", nil)
	req.Header.Set("Authorization",
		fmt.Sprintf("Bearer %s", tokenBody.Token))

	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestEchoJWTGenFailure(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTConfig(testKey).SigningMethod("HS256")

	e, cleanup := NewWebAppBuilder("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy()
	e.POST("/login", c.NewEchoLoginHandler(p))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	// Pass an signing key with invalid value (should be []byte, now
	// we set it to integer) can trigger failed JWT token signing.
	// No worry for breaking interface. In public library we use
	// SigningKey() method which still enforce []byte as input type.
	c.signingKey = 1

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	msg := Message{}
	json.Unmarshal(answer, &msg)
	assert.Equal(t, "Failed to generate JWT token", msg.Msg)

	// Log is printed to support ElasticSearch query
	assert.True(t, strings.Contains(buf.String(),
		"Sign.JWT.Token.Fail"))
}
