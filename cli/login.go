package cli

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/fuzhouch/barton"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ErrUsernameMissing presents error that username command line option
// is missing from configuration file and command line options.
var ErrUsernameMissing = errors.New("MissingUsername")

// ErrPasswordMissing presents error that password command line option
// is missing from configuration file and command line options.
var ErrPasswordMissing = errors.New("MissingPassword")

// HTTPBasicLogin defines a configuration that creates a
// subcommand to request JWT token via HTTP basic config. It does the
// work by taking a combination username and password, plus a remote
// login URL. Then it returns a JWT token remotely, and save to local
// configuration.
type HTTPBasicLogin struct {
	name     string
	Username string `mapstructure:"username"`
	Password string
	LoginURL string `mapstructure:"login_url"`
	JWTToken string `mapstructure:"jwt_token"`
	v        *viper.Viper
	fs       afero.Fs
}

// NewHTTPBasicLogin creates a new configuration object to form a
// login command.
func NewHTTPBasicLogin(name, loginURL string) *HTTPBasicLogin {
	return &HTTPBasicLogin{
		name:     name,
		LoginURL: loginURL,
		v:        viper.GetViper(),
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
// to ensure a correct, layed viper configuration structure.
func (c *HTTPBasicLogin) Viper(v *viper.Viper) {
	c.v = v
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
	c.v.UnmarshalKey(c.name, &c)
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
	if err != nil {
		log.Error().Err(err).Msg("HTTPRequest.Send")
		return err
	}
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

	err = c.v.WriteConfig()
	if err != nil {
		log.Error().Err(err).Msg("WriteConfig")
		return err
	}

	return nil
}
