package barton

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
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
	assert.Equal(t, string(c.signingKey), testKey)

	testKey2 := "test456"
	c.SigningKey([]byte(testKey2)).SigningMethod("HS384")
	assert.Equal(t, c.signingMethod, "HS384")
	assert.Equal(t, string(c.signingKey), testKey2)
}

func TestEchoEnableJWTPreventNoJWTAccess(t *testing.T) {
	testKey := "test123"
	c := NewHMACJWTConfig([]byte(testKey))

	e, cleanup := NewWebAppBuilder("JWTTest").
		EnableHMACJWT(c).
		NewEcho()
	defer cleanup()

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

	e, cleanup := NewWebAppBuilder("JWTTest").
		EnableHMACJWT(c).
		NewEcho()
	defer cleanup()

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

	e, cleanup := NewWebAppBuilder("JWTTest").
		EnableHMACJWT(c).
		NewEcho()
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

func TestEchoDisableJWT(t *testing.T) {
	e, cleanup := NewWebAppBuilder("JWTTest").
		DisableHMACJWT().
		NewEcho()
	defer cleanup()

	e.GET("/test/nojwt", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello!")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test/nojwt", nil)
	e.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	answer, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello!", string(answer))
}
