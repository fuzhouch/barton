package cli

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/fuzhouch/barton"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ErrUsernameMissing presents error that username command line option
// is missing from configuration file and command line options.
var ErrUsernameMissing = errors.New("MissingUsername")

// ErrPasswordMissing presents error that password command line option
// is missing from configuration file and command line options.
var ErrPasswordMissing = errors.New("MissingPassword")

// CommandConfig interface defines interface of creating a subcommand
// for a given CLI object.
type CommandConfig interface {
	Name() string
	NewCobraCMD() *cobra.Command
}

// HTTPBasicLogin defines a configuration that creates a
// subcommand to request JWT token via HTTP basic config. It does the
// work by taking a combination username and password, plus a remote
// login URL. Then it returns a JWT token remotely, and save to local
// configuration.
type HTTPBasicLogin struct {
	parent   CommandConfig
	name     string
	Username string `mapstructure:"username"`
	Password string
	LoginURL string `mapstructure:"login_url"`
	JWTToken string `mapstructure:"jwt_token"`
}

// NewHTTPBasicLogin creates a new configuration object to form a
// login command.
func NewHTTPBasicLogin(name, loginURL string) *HTTPBasicLogin {
	return &HTTPBasicLogin{
		name:     name,
		LoginURL: loginURL,
	}
}

// Name method returns subcommand name.
func (c *HTTPBasicLogin) Name() string {
	return c.name
}

// NewCobraE returns a Cobra's corba.Command object, which reads
// command line and perform login action.
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
		&c.Username,
		"username",
		"u",
		"",
		"Username to perform HTTP basic login")
	cmd.Flags().StringVarP(
		&c.Password,
		"password",
		"p",
		"",
		"Password to perform HTTP basic login")
	cmd.Flags().StringVarP(
		&c.LoginURL,
		"login-url",
		"g",
		c.LoginURL,
		"Remote URL to get login token.")
	return cmd
}

// login method performs a remote login action.
func (c *HTTPBasicLogin) login() error {
	viper.UnmarshalKey(c.name, &c)
	if len(c.Username) == 0 {
		return ErrUsernameMissing
	}
	if len(c.Password) == 0 {
		return ErrPasswordMissing
	}

	req, err := http.NewRequest("POST", c.LoginURL, nil)
	req.SetBasicAuth(c.Username, c.Password)
	cli := &http.Client{
		Timeout: time.Second * 30,
	}
	resp, err := cli.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Err(err).
			Str("loginURL", c.LoginURL).
			Msg("PostLoginURL")
		return err
	}

	body := barton.TokenResponseBody{}
	answer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("ReadResponseBody")
		return err
	}

	err = json.Unmarshal(answer, &body)
	if err != nil {
		log.Error().Err(err).Msg("UnmarshalConfigFile")
		return err
	}

	c.JWTToken = body.Token

	err = viper.WriteConfig()
	if err != nil {
		log.Error().Err(err).Msg("WriteConfig")
		return err
	}

	return nil
}
