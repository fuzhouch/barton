package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fuzhouch/barton"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestSubConfigCreateDefaultDatablock verifies subconfig can create a
// sub-section for login subcommand. The content should be empty.
func TestSubConfigCreateDefaultDatablock(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetFs(fs)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1/")
	root := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		AddSubcommand(login)
	assert.Equal(t, v, login.v)

	cmd, cleanupFunc := root.NewCobraE(nil)
	defer cleanupFunc()

	cmd.SetArgs([]string{"login", "-u", "1", "-p", "2"})
	err := cmd.Execute()
	assert.NotNil(t, err) // Expected: We don't have a valid URL.
	assert.Nil(t, v.Get("test-app.login"))
	assert.Nil(t, v.Get("test-app.login.username"))
	assert.Nil(t, v.Get("test-app.login.token"))
	// All values are empty. The test is set to pass when
	// WE DON'T CRASH!
}

// TestConfigUsernameOverwrittenByCommandline verifies options from command
// line takes higher priority than configuration file.
func TestConfigUsernameOverwrittenByCommandline(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  username: username-config`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9091")
	login.Viper(v, "test-app3")
	login.AferoFS(fs)
	v.ReadInConfig()

	// Case 1: Username in config file is overwritten by command line
	login.username = "username-cmd"
	login.password = "password-cmd"
	err := login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "username-cmd", login.username)

	login.username = ""
	login.password = "password-cmd"
	err = login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "username-config", login.username)
}

// TestConfigUsernameEmptyTriggerError verifies an error is triggered
// when username is unspecified from anywhere.
func TestConfigUsernameEmptyTriggerError(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  login-url: http://127.0.0.1:5050`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9091")
	login.Viper(v, "test-app3")
	login.AferoFS(fs)
	v.ReadInConfig()

	login.username = ""
	login.password = ""
	err := login.readConfig()
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrUsernameMissing))
}

// TestConfigPasswordEmptyAlwaysTriggerError verifies empty password
// should always trigger error.
func TestConfigPasswordEmptyAlwaysTriggerError(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  username: username-config`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9091")
	login.Viper(v, "test-app3")
	login.AferoFS(fs)
	v.ReadInConfig()

	login.username = "username-cmd"
	login.password = ""
	err := login.readConfig()
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrPasswordMissing))
}

// TestConfigPasswordAlwaysIgnoreConfigFile verifies configuration file
// is already ignored when reading password.
func TestConfigPasswordAlwaysIgnoreConfigFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  username: username-config
  password: password-config`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9091")
	login.Viper(v, "test-app3")
	login.AferoFS(fs)
	v.ReadInConfig()

	login.username = "username-cmd"
	login.password = ""
	err := login.readConfig()
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrPasswordMissing))
}

// TestConfigLoginURLRead verifies behavior of LoginURL reading
// logic. This is specifically designed to distinguish three scenarios.
func TestConfigLoginURLRead(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9090/")
	login.Viper(v, "test-app4")
	login.AferoFS(fs)

	// Case 1: login-url in config, unspecified in command line.
	// Still pick configuration file.
	afero.WriteFile(fs, "config.yml", []byte(`
test-app4:
  login-url: http://127.0.0.1:5050`), 0644)
	v.ReadInConfig()

	cmd := login.NewCobraE()
	err := cmd.ParseFlags([]string{"-u", "usr", "-p", "pwd"})
	assert.Nil(t, err)
	err = login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "http://127.0.0.1:5050", login.loginURL)

	// Case 2: login-url in config, also specified in command line.
	// Use command line version.
	cmd = login.NewCobraE()
	err = cmd.ParseFlags([]string{
		"-u", "usr",
		"-p", "pwd",
		"-g", "http://127.0.0.1:8080/"})
	assert.Nil(t, err)
	err = login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/", login.loginURL)

	// Case 3: login-url in config, also specified in command line
	// with a value same with default values.
	// Use command line version.
	cmd = login.NewCobraE()
	err = cmd.ParseFlags([]string{
		"-u", "usr",
		"-p", "pwd",
		"-g", "http://127.0.0.1:9090/",
	})
	assert.Nil(t, err)
	err = login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "http://127.0.0.1:9090/", login.loginURL)

	// Case 4: login-url is unspecified anywhere. Use default
	// version. In this case we recreate a v2 Viper configuration to
	// avoid settings from prevoius test
	v2 := viper.New()
	v2.SetConfigFile("config2.yml")
	v2.SetFs(fs)
	afero.WriteFile(fs, "config2.yml", []byte(`
test-app5:
  username: testuser
`), 0644)
	v2.ReadInConfig()
	login.Viper(v2, "test-app5")

	cmd = login.NewCobraE()
	err = cmd.ParseFlags([]string{
		"-u", "usr",
		"-p", "pwd",
	})
	assert.Nil(t, err)
	err = login.readConfig()
	assert.Nil(t, err)
	assert.Equal(t, "http://127.0.0.1:9090/", login.loginURL)
}

// TestConfigReadFromBadFormatTriggerError verifies login subcommand
// returns error on bad format. This is a corner case, because
// subcommand is used with rootCLI, which has already parsed
// configuration file. However, it's still useful in cases, that login
// subcommand is used separatedly.
func TestConfigReadFromBadFormatTriggerError(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  username:[1,2,3]`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:9091")
	login.Viper(v, "test-app3")
	login.AferoFS(fs)
	v.ReadInConfig()

	login.username = "username-cmd"
	login.password = ""
	err := login.readConfig()
	// username should be string, thus we should see a failure on
	// unmarshalling.
	assert.NotNil(t, err)
}

// TestInvalidWebURLReturnFailure verifies an invalid URL can trigger
// error returned when parsing login.
func TestInvalidWebURLReturnFailure(t *testing.T) {
	buf := bytes.NewBufferString("")
	zc := barton.NewZerologConfig().SetWriter(buf)
	zc.SetGlobalPolicy().SetGlobalLogger()

	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`
test-app3:
  username: username-config`), 0644)

	// Trigger an error at http.NewRequest() according to RFC3986.
	login := NewHTTPBasicLogin("login", "1:2://test")
	login.Viper(v, "test-app")
	login.AferoFS(fs)
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{"--username", "u", "--password", "pwd"})
	err := cmd.Execute()
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(buf.String(), "NewRequest.Fail"),
		"NewRequestFail log line should exist")
}

// TestConfigMissingParamCauseErrorCobra verifies a missing of
// required parameter causes error on calling cobra.Command.Execute()
func TestConfigMissingParamCauseErrorCobra(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetConfigFile("config.yml")
	v.SetFs(fs)
	afero.WriteFile(fs, "config.yml", []byte(`test-app:`), 0644)

	login := NewHTTPBasicLogin("login", "http://127.0.0.1:8080/")
	login.Viper(v, "test-app")
	login.AferoFS(fs)
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{"--password", "pwd"})
	err := cmd.Execute()
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrUsernameMissing))
}

// TestWriteConfigOnSuccess verifies configuration is written to
// configuration file when token is received.
func TestWriteConfigOnSuccess(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				response := barton.TokenResponseBody{
					Token:  "mock_token_1",
					Expire: time.Now().Unix(),
				}
				body, _ := json.Marshal(response)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			}))
	defer mockServer.Close()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	login.cli = mockServer.Client() // Overwrite prod client.
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{
		"--username", "usr",
		"--password", "pwd",
	})
	err := cmd.Execute()
	assert.Nil(t, err)

	username := v.GetString("test-app.username")
	loginURL := v.GetString("test-app.login-url")
	jwtToken := v.GetString("test-app.token")
	assert.Equal(t, "usr", username)
	assert.Equal(t, mockServer.URL, loginURL)
	assert.Equal(t, "mock_token_1", jwtToken)

	res, err := afero.ReadFile(fs, "./config.yml")
	content := string(res)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(content, "test-app:"))
	assert.True(t, strings.Contains(content,
		"  token: mock_token_1"))
	assert.True(t, strings.Contains(content,
		fmt.Sprintf("  login-url: %s", mockServer.URL)))
	assert.True(t, strings.Contains(content, "  username: usr"))
}

// TestWriteConfigErrorHandling verifies error handling logic when
// there's an error writing configuration.
func TestWriteConfigErrorHandling(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				response := barton.TokenResponseBody{
					Token:  "mock_token_1",
					Expire: time.Now().Unix(),
				}
				body, _ := json.Marshal(response)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			}))
	defer mockServer.Close()

	// A readonly file system triggers writing error on calling is
	// done.
	mem := afero.NewMemMapFs()
	fs := afero.NewReadOnlyFs(mem)
	afero.WriteFile(mem, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	login.cli = mockServer.Client() // Overwrite prod client.
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{
		"--username", "usr",
		"--password", "pwd",
	})
	err := cmd.Execute()

	// Operation is not permitted, thus, error will trigger
	assert.NotNil(t, err)

	// Also verify content of config.yml is unchanged.
	username := v.GetString("test-app.username")
	loginURL := v.GetString("test-app.login-url")
	jwtToken := v.GetString("test-app.token")
	assert.Equal(t, "usr", username)
	assert.Equal(t, mockServer.URL, loginURL)
	assert.Equal(t, "mock_token_1", jwtToken)

	res, err := afero.ReadFile(fs, "./config.yml")
	content := string(res)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(content, "test-app:"))
	assert.False(t, strings.Contains(content,
		"  token: mock_token_1"))
	assert.False(t, strings.Contains(content,
		fmt.Sprintf("  login-url: %s", mockServer.URL)))
	assert.False(t, strings.Contains(content, "  username: usr"))
}

// TestClientStatusCodeErrorHandling verifies an error is returned when
// http status code is not OK.
func TestClientStatusCodeErrorHandling(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				response := barton.TokenResponseBody{
					Token:  "mock_token_1",
					Expire: time.Now().Unix(),
				}
				body, _ := json.Marshal(response)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(body)
			}))
	defer mockServer.Close()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	login.cli = mockServer.Client() // Overwrite prod client.
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{
		"--username", "usr",
		"--password", "pwd",
	})
	err := cmd.Execute()
	assert.NotNil(t, err)

	errLogin, ok := err.(*LoginHTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, errLogin.StatusCode)
	assert.Equal(t, "HTTPLoginError:Code=400", errLogin.Error())

	// Parameter is not written.
	username := v.GetString("test-app.username")
	loginURL := v.GetString("test-app.login-url")
	jwtToken := v.GetString("test-app.token")
	assert.Equal(t, "", username)
	assert.Equal(t, "", loginURL)
	assert.Equal(t, "", jwtToken) // Not retrieved

	// File is not written. Note that fs is actually writable.
	res, err := afero.ReadFile(fs, "./config.yml")
	content := string(res)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(content, "test-app:"))
	assert.False(t, strings.Contains(content,
		"  token: mock_token_1"))
	assert.False(t, strings.Contains(content,
		fmt.Sprintf("  login-url: %s", mockServer.URL)))
	assert.False(t, strings.Contains(content, "  username: usr"))
}

// TestClientContentUnmarshalErrorHandling verifies login subcommand
// returns error when received content is not valid JSON.
func TestClientContentUnmarshalErrorHandling(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("invalid JSON"))
			}))
	defer mockServer.Close()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	login.cli = mockServer.Client() // Overwrite prod client.
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{
		"--username", "usr",
		"--password", "pwd",
	})
	err := cmd.Execute()
	assert.NotNil(t, err)

	// Parameter is not written.
	username := v.GetString("test-app.username")
	loginURL := v.GetString("test-app.login-url")
	jwtToken := v.GetString("test-app.token")
	assert.Equal(t, "", username)
	assert.Equal(t, "", loginURL)
	assert.Equal(t, "", jwtToken) // Not retrieved

	// File is not written. Note that fs is actually writable.
	res, err := afero.ReadFile(fs, "./config.yml")
	content := string(res)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(content, "test-app:"))
	assert.False(t, strings.Contains(content,
		"  token: mock_token_1"))
	assert.False(t, strings.Contains(content,
		fmt.Sprintf("  login-url: %s", mockServer.URL)))
	assert.False(t, strings.Contains(content, "  username: usr"))
}

type errReader int

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("Test error")
}

func TestCallAPIFailOnSendRequestErrorHandling(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				response := barton.TokenResponseBody{
					Token:  "mock_token_1",
					Expire: time.Now().Unix(),
				}
				body, _ := json.Marshal(response)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(body)
			}))
	defer mockServer.Close()

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	badBuf := errReader(0)
	badReq, err := http.NewRequest("POST", mockServer.URL, badBuf)
	assert.Nil(t, err)
	err = login.callAPI(badReq)
	assert.NotNil(t, err)

	content := b.String()
	assert.True(t, strings.Contains(content, "HTTPRequest.Send.Fail"))
}

// TestCallAPIHTTPRequestReadBodyError verifies login subcommand handles
// error on failure of reading response body.
func TestCallAPIHTTPRequestReadBodyError(t *testing.T) {
	mockServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// XXX Don't set WriteHeader here! If
				// it's set, The ioutil.ReadAll() at
				// client side will not check
				// Content-Length.
				// w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Length", "256")
				// Make sure we return no content but
				// set length to > 0. This forces
				// response body triggers and error.
			}))
	defer mockServer.Close()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./config.yml", []byte("test-app:"), 0644)

	v := viper.New()
	v.SetConfigFile("./config.yml")
	v.SetFs(fs)
	v.ReadInConfig()

	login := NewHTTPBasicLogin("login", mockServer.URL)
	login.Viper(v, "test-app")
	login.AferoFS(fs)

	login.cli = mockServer.Client() // Overwrite prod client.
	cmd := login.NewCobraE()
	cmd.SetArgs([]string{
		"--username", "usr",
		"--password", "pwd",
	})
	err := cmd.Execute()
	assert.NotNil(t, err)

	// Parameter is not written.
	username := v.GetString("test-app.username")
	loginURL := v.GetString("test-app.login-url")
	jwtToken := v.GetString("test-app.token")
	assert.Equal(t, "", username)
	assert.Equal(t, "", loginURL)
	assert.Equal(t, "", jwtToken) // Not retrieved

	// File is not written. Note that fs is actually writable.
	res, err := afero.ReadFile(fs, "./config.yml")
	content := string(res)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(content, "test-app:"))
	assert.False(t, strings.Contains(content,
		"  token: mock_token_1"))
	assert.False(t, strings.Contains(content,
		fmt.Sprintf("  login-url: %s", mockServer.URL)))
	assert.False(t, strings.Contains(content, "  username: usr"))
}
