package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/fuzhouch/barton"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ErrUsernameMissing presents error that username option is
// unspecified in neither command line nor configuration file.
var ErrUsernameMissing = errors.New("MissingUsername")

// ErrPasswordMissing presents error that password option is
// unspecified in neither command line nor configuration file.
var ErrPasswordMissing = errors.New("MissingPassword")

// ErrLoginURLMissing presents error that login URL option is
// unspecified in neither command line nor configuration file.
var ErrLoginURLMissing = errors.New("MissingLoginURL")

// LoginHTTPError is an error object that returns on HTTP code error.
type LoginHTTPError struct {
	StatusCode int
}

// Error method prints error message of LoginHTTPError
func (e LoginHTTPError) Error() string {
	return fmt.Sprintf("HTTPLoginError:Code=%d", e.StatusCode)
}

type loginConfig struct {
	Username string `mapstructure:"username"`
	LoginURL string `mapstructure:"auth-url"`
	JWTToken string `mapstructure:"token"`
}

// HTTPBasicLogin defines a configuration that creates a
// subcommand to request JWT token via HTTP basic config. It does the
// work by taking a combination username and password, plus a remote
// login URL. Then it returns a JWT token remotely, and save to local
// configuration.
type HTTPBasicLogin struct {
	name             string
	username         string
	password         string
	loginURL         string
	jwtToken         string
	v                *viper.Viper
	fs               afero.Fs
	cli              *http.Client
	section          string
	fallbackLoginURL string
}

// NewHTTPBasicLogin creates a new configuration object to form a
// login command.
func NewHTTPBasicLogin(name, fallbackLoginURL string) *HTTPBasicLogin {
	return &HTTPBasicLogin{
		name:             name,
		fallbackLoginURL: fallbackLoginURL,
		v:                viper.GetViper(),
		cli: &http.Client{
			// TODO In future version timeout should be
			// configurable.
			Timeout: time.Second * 30,
		},
		section: name,
	}
}

// Name method returns name of subcommand.
func (c *HTTPBasicLogin) Name() string {
	return c.name
}

// Viper method sets a new Viper instance to read configuration. In most
// case this function can be ignored. It's useful when working with unit
// test or setting namespace from a sub-section of viper instance. For
// HTTPBasicLogin command, it's called by RootCLI.AddSubcommand() method
// to ensure a correct, layed viper configuration structure. This method
// also takes a string that represents root section of subcommand.
func (c *HTTPBasicLogin) Viper(v *viper.Viper, section string) {
	c.v = v
	c.section = section
}

// AferoFS method sets an instance of afero.Fs to decide the file
// system we want to write to. Same with RootCLI. This method is useful
// during unit test. Similar with Viper() method, it's called by
// RootCLI.AddSubcommand() to ensure a consistent file system target.
func (c *HTTPBasicLogin) AferoFS(fs afero.Fs) {
	c.fs = fs
}

// NewCobraE returns a Cobra's corba.Command object, which reads
// command line and perform login action. Unlike RootCLI, it does not
// pass customized RunE function from parameter, since sub-command
// should be done quickly.
func (c *HTTPBasicLogin) NewCobraE() *cobra.Command {
	cmd := &cobra.Command{
		Use:   c.name,
		Short: "Login command with HTTP basic login",
		Long:  "Login command with HTTP basic login",
		RunE: func(cc *cobra.Command, args []string) error {
			return c.login()
		},
	}
	cmd.Flags().StringVarP(
		&c.username,
		"username",
		"u",
		"",
		"Username to perform HTTP basic login")
	cmd.Flags().StringVarP(
		&c.password,
		"password",
		"p",
		"",
		"Password to perform HTTP basic login")
	cmd.Flags().StringVarP(
		&c.loginURL,
		"auth",
		"a",
		"",
		"Remote URL to authenticate and grant tokens.")
	return cmd
}

func (c *HTTPBasicLogin) callAPI(req *http.Request) error {
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.cli.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("HTTPRequest.Send.Fail")
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := &LoginHTTPError{StatusCode: resp.StatusCode}
		log.Error().Err(err).
			Str("loginURL", c.loginURL).
			Msg("PostLoginURL")
		return err
	}

	answer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("ReadResponseBody")
		return err
	}

	body := barton.TokenResponseBody{}
	err = json.Unmarshal(answer, &body)
	if err != nil {
		log.Error().Err(err).Msg("UnmarshalConfigFile")
		return err
	}

	c.jwtToken = body.Token
	return nil
}

func (c *HTTPBasicLogin) readConfig() error {
	cfg := loginConfig{}
	// Before calling to here, we have got username, password and
	// loginURL from command line.
	err := c.v.UnmarshalKey(c.section, &cfg)
	if err != nil {
		log.Error().
			Err(err).
			Str("section", c.section).
			Msg("UnmarshalConfigKey")
		return err
	}
	// A common logic: Parameter from command line can overwrite
	// values in configuration file.
	if len(c.username) == 0 && len(cfg.Username) > 0 {
		log.Info().Msg("FallbackToConfigFile.Username")
		c.username = cfg.Username
	}

	if len(c.loginURL) > 0 {
		// Value specified from command line.
		log.Info().Str("url", c.loginURL).Msg("LoginURL.Cmdline")
	} else if len(cfg.LoginURL) > 0 {
		c.loginURL = cfg.LoginURL
		log.Info().Str("url", c.loginURL).Msg("LoginURL.Config")
	} else {
		log.Info().Str("url", c.loginURL).Msg("LoginURL.Fallback")
		c.loginURL = c.fallbackLoginURL
	}

	if len(c.username) == 0 {
		log.Error().Err(ErrUsernameMissing).
			Msg("BasicHTTP.ReadConfig.UsernameMissing")
		return ErrUsernameMissing
	}

	// Password or JWT token: For login subcommand, we always need
	// password from command line, and overwrite token. So
	// password should always not nil.
	if len(c.password) == 0 {
		log.Error().Err(ErrPasswordMissing).
			Msg("BasicHTTP.ReadConfig.PasswordMissing")
		return ErrPasswordMissing
	}
	return nil
}

func (c *HTTPBasicLogin) login() error {
	err := c.readConfig()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.loginURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("NewRequest.Fail")
		return err
	}

	err = c.callAPI(req)
	if err != nil {
		return err
	}

	c.v.Set(fmt.Sprintf("%s.username", c.section), c.username)
	c.v.Set(fmt.Sprintf("%s.auth-url", c.section), c.loginURL)
	c.v.Set(fmt.Sprintf("%s.token", c.section), c.jwtToken)

	// TODO Here's a potential security hole, that when parent
	// command loads configuration from a writable
	// config file at global path, say /etc/app/config.yml, a jwt
	// token is written to the global readable file. However, it's
	// fairly hard to prevent such attack in application level, as
	// client application does not have enough knowledge to decide
	// which config file path should be considered dangerous.
	// Let's set it as is and see what we can think of.
	configFileSelected := c.v.ConfigFileUsed()
	err = c.v.WriteConfigAs(configFileSelected)
	if err != nil {
		log.Error().Err(err).Msg("WriteConfig")
		return err
	}
	return nil
}
