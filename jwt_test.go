package barton

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
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
	c := NewHMACJWTGen([]byte(testKey))
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
	c := NewHMACJWTGen([]byte(testKey))

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoAuthMiddleware())

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/nojwt", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEchoEnableJWTPreventInvalidJWTAccess(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey)

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoAuthMiddleware())

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
	c := NewHMACJWTGen(testKey).SigningMethod("HS384")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	e.Use(c.NewEchoAuthMiddleware())
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

func newBasicAuthPolicy(gen JWTGen) *JWTBuilder {
	// For simplicity reason, we don't use cached version. Please
	// refer to https://github.com/shaj13/go-guardian and see
	// _example/basic/main.go for a start.
	//
	// NOTE: Don't forget to register global replacement policy
	// function for fifo, or we will see a runtime panic.
	//     import _ "github.com/shaj13/libcache/fifo"
	//
	// Code sample below:
	// cache := libcache.FIFO.New(0)
	// cache.SetTTL(time.Minute * 5)
	// cache.RegisterOnExpired(func(key, _ interface{}) {
	//	cache.Peek(key)
	// })
	// strategy := basic.NewCached(validate, cache)
	// return NewJWTGenPolicy(strategy)

	strategy := basic.New(validate)
	return NewJWTBuilder(strategy, gen)
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

// TestEchoJWTLoginHandler tests default login Handler can be used to
// generate JWT token, with a basic authentication login handler. Note
// that the basic auth username and password are sent via Authorization
// header with Basic prefix.
func TestEchoJWTLoginHandler(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS384")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	g := e.Group("/v1", p.NewEchoAuthMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	e.POST("/login", p.NewEchoLoginHandler())

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
	tokenBody := TokenResponseBody{}
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
		"Authenticate.Success.JWT.Issued"))
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

// TestEchoReturnJWTTokenCustomizedLogs tests a customized log line is
// printed, when a JWT token is generated successfully. The log line is
// customized via TokenIssuedLogMsg(). When the log line is printed,
// the user name is also printed in log line.
//
// The log text is printed to ensure developers know which log line to
// search in analytic engine like ElasticSearch.
func TestEchoReturnJWTTokenCustomizedLogs(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS384")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c).TokenIssuedLogMsg("Bravo!")
	e.POST("/login", p.NewEchoLoginHandler())

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
	tokenBody := TokenResponseBody{}
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

// TestEchoBadAuthenticationNoLog tests a default log line is not printed
// on authentication error, when PrintAuthFailLog() is set to false.
func TestEchoBadAuthenticationNoLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler())

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

// TestEchoBadAuthenticationPrintLog tests a default log line is printed
// on authentication error, when PrintAuthFailLog() is set to true.
// The log text is printed to ensure developers know which log line to
// search in analytic engine like ElasticSearch.
func TestEchoBadAuthenticationPrintLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c).PrintAuthFailLog(true)
	e.POST("/login", p.NewEchoLoginHandler())

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

// TestEchoBadAuthenticationPrintCustomizedLog tests an customized error
// log line can be specified by AuthFailLogMsg() API, printed on
// authenticaion error. The log text is configurable to ensure
// developers know which log line to search in analytic engine like
// ElasticSearch.
func TestEchoBadAuthenticationPrintCustomizedLog(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c).
		AuthFailLogMsg("Don't Panic!").
		PrintAuthFailLog(true)
	e.POST("/login", p.NewEchoLoginHandler())

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

// TestEchoReturnJWTTokenWithShorterExpireSpan test a sceanrio that an
// expired JWT token can't be used to access API. It's done by
// intentionally set an ExpireSpan configuration to always generate a
// token with expiration time span set to 1 hour ago.
func TestEchoReturnJWTTokenWithShorterExpireSpan(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS384")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	g := e.Group("/v1", c.NewEchoAuthMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	// Always return expired token
	p := newBasicAuthPolicy(c).ExpireSpan(time.Hour * -1)
	e.POST("/login", p.NewEchoLoginHandler())

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
	tokenBody := TokenResponseBody{}
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
		"Authenticate.Success.JWT.Issued"))
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

// TestEchoJWTGenFailure intentionally triggers an internal key signing
// error by force assigning SigningKey to 1 instead byte string. In this
// context, an error log with name Sign.JWT.Token.Fail is printed and
// http code 500 is returned.
func TestEchoJWTGenFailure(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler())

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

// TestEchoLookupJWTTokenFromContext demonstrates how to receive user
// name from JWT token stored in context, with default lookup key name
// as "user".
func TestEchoLookupJWTTokenFromContext(t *testing.T) {
	testKey := []byte("test123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS384")
	token, err := c.NewTokenStr(jwt.MapClaims{
		"exp":  time.Now().Add(time.Hour * 1).Unix(),
		"name": "tu",
	})
	assert.Nil(t, err)

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	e.Use(c.NewEchoAuthMiddleware())
	e.GET("/hello", func(c echo.Context) error {
		user, ok := c.Get("user").(*jwt.Token)
		assert.True(t, ok)
		claims, ok := user.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, "tu", claims["name"])
		return c.String(http.StatusOK, "hello!")
	})

	// Received token can be used to call APIs.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hello", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello!", string(answer))
}

// TestEchoJWTMetricsDefaultName verifies the metrics name without
// prefix always start from Barton_.
func TestEchoJWTMetricsDefaultName(t *testing.T) {
	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler()) // No prefix!

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

	// Read metrics: supposed a metrics called
	// JWTTest_defaultLogin_jwt_internal_error_count is set to 1
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	assert.True(t, strings.Contains(string(body),
		"Barton_jwt_internal_error_count 1"))
}

// TestEchoJWTMetricsCustomizedName verifies the metrics for internal
// auth error can be printed.
func TestEchoJWTMetricsCustomizedName(t *testing.T) {
	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler("defaultLogin"))

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

	// Read metrics: supposed a metrics called
	// JWTTest_defaultLogin_jwt_internal_error_count is set to 1
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	assert.True(t, strings.Contains(string(body),
		"defaultLogin_jwt_internal_error_count 1"))
}

// TestEchoJWTMetricsMultiplePrefixTakeOne verifies when multiple prefix
// is specified in NewEchoLoginHandler(), only the first prefix is
// taken, the others are ignored.
func TestEchoJWTMetricsMultiplePrefixTakeOne(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler(
		"defaultLogin2", "skipped"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	_, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read metrics: supposed a metrics called
	// JWTTest_defaultLogin_jwt_internal_error_count is set to 1
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	assert.True(t, strings.Contains(string(body),
		"defaultLogin2_jwt_issued_count 1"))

	// Check log line is printed successfully.
	assert.True(t, strings.Contains(buf.String(),
		"HandlerIdentifier.TakeFirstOne"))
}

// TestEchoJWTMetricsFailedMetrics tests Prometheus metrics for failed
// authentication is printed.
func TestEchoJWTMetricsFailedMetrics(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler("defaultLoginS"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	cred := []byte("testuser:badpassword")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	_, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Read metrics: supposed a metrics called
	// JWTTest_defaultLogin_jwt_internal_error_count is set to 1
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	assert.True(t, strings.Contains(string(body),
		"defaultLoginS_jwt_failed_auth_count 1"))
}

// TestEchoJWTMetricsMultipleHandlers verifies multiple login handlers
// uses independent metrics settings, as far as they fill with different
// names.
func TestEchoJWTMetricsMultipleHandlers(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123") // Empty key causes signing falure
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login1", p.NewEchoLoginHandler("login1"))
	e.POST("/login2", p.NewEchoLoginHandler("login2"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login1", nil)
	cred := []byte("testuser:badpassword")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	_, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/login2", nil)
	cred = []byte("testuser:testpwd")
	req.Header.Set("Authorization",
		fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString(cred)))

	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("User-Agent", "Golang_UT")
	e.ServeHTTP(w, req)

	// Two metrics should be completely independent.
	response := w.Result()
	body, _ := io.ReadAll(response.Body)
	assert.True(t, strings.Contains(string(body),
		"login1_jwt_failed_auth_count 1"))
	assert.True(t, strings.Contains(string(body),
		"login1_jwt_issued_count 0"))
	assert.True(t, strings.Contains(string(body),
		"login2_jwt_issued_count 1"))
	assert.True(t, strings.Contains(string(body),
		"login2_jwt_failed_auth_count 0"))

	// Note: it also tests globalCleanup() function here as it does
	// not crash.
}

type LogRequestContent struct {
	Level       string `json:"level"`
	Auth        bool   `json:"auth"`
	User        string `json:"user"`
	Scheme      string `json:"scheme"`
	Request     string `json:"request"`
	QueryString string `json:"querystr"`
}

// TestJWTLogRequestWithToken verifies request is logged with middleware
// enabled. A log line with message as "IncomingRequest" is printed.
func TestJWTLogRequestWithToken(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTestLogRequest").NewEcho()
	defer cleanup()

	p := newBasicAuthPolicy(c)
	e.POST("/login", p.NewEchoLoginHandler())

	g := e.Group("/v1", c.NewEchoAuthMiddleware())
	g.Use(p.NewEchoLogRequestMiddleware()) // Log request
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

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
	tokenBody := TokenResponseBody{}
	json.Unmarshal(answer, &tokenBody)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v1/hello?to=world", nil)
	req.Header.Set("Authorization",
		fmt.Sprintf("Bearer %s", tokenBody.Token))
	e.ServeHTTP(w, req)
	resp = w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	verified := false
	jsonMsgs := strings.Split(buf.String(), "\n")
	for _, j := range jsonMsgs {
		if strings.Contains(j, "IncomingRequest") {
			var content LogRequestContent
			err := json.Unmarshal([]byte(j), &content)
			assert.Nil(t, err)
			assert.Equal(t, true, content.Auth)
			assert.Equal(t, "testuser", content.User)
			assert.Equal(t, "http", content.Scheme)
			assert.Equal(t, "/v1/hello", content.Request)
			assert.Equal(t, "to=world", content.QueryString)
			verified = true
		}
	}
	assert.True(t, verified, "LogMessageNotFound:IncomingRequest")
}

// TestJWTLogRequestWithToken verifies request is logged with middleware
// enabled. A log line with message as "IncomingRequest" is printed.
// Note that in this case, the log line is printed when there's no
// authentication enabled.
func TestJWTLogRequestWithoutToken(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTestLogRequestNoAuth").NewEcho()
	defer cleanup()

	// We don't really use JWT, but just create middleware.
	p := newBasicAuthPolicy(c)
	g := e.Group("/v1", p.NewEchoLogRequestMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/hello?to=world", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	verified := false
	jsonMsgs := strings.Split(buf.String(), "\n")
	for _, j := range jsonMsgs {
		if strings.Contains(j, "IncomingRequest") {
			var content LogRequestContent
			err := json.Unmarshal([]byte(j), &content)
			assert.Nil(t, err)
			assert.Equal(t, false, content.Auth)
			assert.Equal(t, "info", content.Level)
			assert.Equal(t, "", content.User)
			assert.Equal(t, "http", content.Scheme)
			assert.Equal(t, "/v1/hello", content.Request)
			assert.Equal(t, "to=world", content.QueryString)
			verified = true
		}
	}
	assert.True(t, verified, "LogMessageNotFound:IncomingRequest")
}

// TestJWTLogRequestCustomizedLogMessage verifies a customized message
// other than by-default "IncomingRequest" is used.
func TestJWTLogRequestCustomizedLogMessage(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTestLogRequestMyMsg").NewEcho()
	defer cleanup()

	// We don't really use JWT, but just create middleware.
	p := newBasicAuthPolicy(c).RequestLogMsg("TestRequestHey")
	g := e.Group("/v1", p.NewEchoLogRequestMiddleware())
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/hello?to=world", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	verified := false
	jsonMsgs := strings.Split(buf.String(), "\n")
	for _, j := range jsonMsgs {
		if strings.Contains(j, "TestRequestHey") {
			var content LogRequestContent
			err := json.Unmarshal([]byte(j), &content)
			assert.Nil(t, err)
			assert.Equal(t, false, content.Auth)
			assert.Equal(t, "info", content.Level)
			assert.Equal(t, "", content.User)
			assert.Equal(t, "http", content.Scheme)
			assert.Equal(t, "/v1/hello", content.Request)
			assert.Equal(t, "to=world", content.QueryString)
			verified = true
		}
	}
	assert.True(t, verified, "LogMessageNotFound:TestRequestHey")
}

func BadContextMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Set("user", "intentionally-trigger-parse-error")
		return next(c)
	}
}

// TestJWTLogRequestParseError verifies a log message is printed when
// JWT context can't be parsed successfully.
func TestJWTLogRequestParseError(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := NewZerologConfig().SetWriter(buf).UseUTCTime()
	zc.SetGlobalPolicy().SetGlobalLogger()

	testKey := []byte("key123")
	c := NewHMACJWTGen(testKey).SigningMethod("HS256")

	e, cleanup := NewWebApp("JWTTestLogRequestError").NewEcho()
	defer cleanup()

	// We don't really use JWT, but just create middleware.
	p := newBasicAuthPolicy(c).RequestLogMsg("TestRequestError")
	g := e.Group("/v1",
		BadContextMiddleware,            // Insert bad context
		p.NewEchoLogRequestMiddleware()) // Then trigger error
	g.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/hello?to=world", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	verified := false
	jsonMsgs := strings.Split(buf.String(), "\n")
	for _, j := range jsonMsgs {
		if strings.Contains(j, "TestRequestError") {
			var content LogRequestContent
			err := json.Unmarshal([]byte(j), &content)
			assert.Nil(t, err)
			assert.Equal(t, true, content.Auth)
			assert.Equal(t, "error", content.Level)
			assert.Equal(t, "", content.User)
			assert.Equal(t, "http", content.Scheme)
			assert.Equal(t, "/v1/hello", content.Request)
			assert.Equal(t, "to=world", content.QueryString)
			verified = true
		}
	}
	assert.True(t, verified, "LogMessageNotFound:TestRequestError")
}
