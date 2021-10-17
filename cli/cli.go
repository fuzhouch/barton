package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fuzhouch/barton"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// SubcommandBuilder provides a interface that all subcommand builders
// needs to provide. They are used by RootCLI to configure subcommand
// creation.
type SubcommandBuilder interface {
	Name() string
	Viper(*viper.Viper, string)
	AferoFS(afero.Fs)
	NewCobraE() *cobra.Command
}

// RootCLI configures a root client command line interface.
type RootCLI struct {
	appName     string
	configFile  string
	logFile     string
	fs          afero.Fs
	v           *viper.Viper
	subCommands map[string]SubcommandBuilder
}

// NewRootCLI creates a new command line configuration object. It
// takes configurations and create an cobra.Command object. RootCLI
// returns a root cobra.Command object with a pre-configured
// cobra.Command.RunE function, which handles proper cleanup operations.
func NewRootCLI(appName string) *RootCLI {
	return &RootCLI{
		appName:     appName,
		fs:          afero.NewOsFs(),
		v:           viper.GetViper(),
		subCommands: make(map[string]SubcommandBuilder),
	}
}

// AferoFS method sets an instance of afero.Fs to decide the file
// system we want to write to. In most cases we can just leave it unset
// as it points to an afero.OsFs object for all regular filesystem based
// calls. This API is useful for unit test, which allows we set memory
// file system.
func (c *RootCLI) AferoFS(fs afero.Fs) *RootCLI {
	c.fs = fs
	return c
}

// Viper method sets a new Viper instance to read configuration. In most
// case this function can be ignored. It's useful when working with unit
// test or configure a remote readable configuration setting.
func (c *RootCLI) Viper(v *viper.Viper) *RootCLI {
	c.v = v
	return c
}

// CobraRunEFunc is the type of Cobra's command processor function, used
// by cobra.Command.RunE.
type CobraRunEFunc = func(*cobra.Command, []string) error

// CleanupFunc is the type of cleanup function returned by Barton.
// CleanupFunc instances releases resource gracefully.
type CleanupFunc = func()

// NewCobraE methods creates a Cobra's cobra.Command object that represents
// root command line interface. It takes function object to fill
// cobra's RunE field. If there's no speical step to process, pass nil.
//
// Besides returning cobra.Command, this function also returns a cleanup
// function, which should be called before program exits. For RootCLI
// case, it closes log files and configuration file properly.
//
// The reason we introduce this cleanup function is because cobra does
// not offer a good way to handle it properly. By the time the code is
// written (2021-10), Cobra 1.2.1 offers only PersisentPreRunE hook to
// allow subcommands run a hook from root. However, this does not work
// for our scenario because the corresponding API, PersistentPostRunE,
// is not invoked on completion of subcommand. Thus, it's necessary
// to wrap the calling sequence to ensure config files or logs are
// properly closed without losing data.
func (c *RootCLI) NewCobraE(run CobraRunEFunc) (*cobra.Command, CleanupFunc) {
	cleanupFunc := func() { log.Info().Msg("Cleanup.NoAction.Bye") }
	cmd := &cobra.Command{
		Use:   c.appName,
		Short: fmt.Sprintf("CLI for %s", c.appName),
		Long:  fmt.Sprintf("CLI for %s", c.appName),
		RunE: func(cc *cobra.Command, args []string) error {
			if run != nil {
				return run(cc, args)
			}
			return nil
		},
		PersistentPreRunE: func(cc *cobra.Command, args []string) error {
			logCleanup, err := c.loadLog(cc)
			if err != nil {
				return err
			}

			configCleanup, err := c.loadConfig(cc)
			if err != nil {
				return err
			}

			cleanupFunc = func() {
				log.Info().Msg("Cleanup.Bye")
				configCleanup()
				logCleanup()
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(
		&c.configFile,
		"config",
		"c",
		"",
		"Path to config file. Omitted to use default search paths.")
	cmd.PersistentFlags().StringVarP(
		&c.logFile,
		"log",
		"l",
		"",
		"Path to log file. If omitted, writes to stdout.")

	// XXX Please always keep in mind that the two root options,
	// --config and --log should NEVER be bound to any keys in
	// config file.
	//
	// It's obvious that --config must be read from command line
	// explicitly: there's no way for us to read configuration file
	// name from a configuration body. Meanwhile, --log option is a
	// mandatory option to read from command line because I don't
	// want to introduce a dependency between logging and
	// configuration file. Thus, an error when reading confiugration
	// file can always be logged.
	for _, sub := range c.subCommands {
		cmd.AddCommand(sub.NewCobraE())
	}
	return cmd, func() { cleanupFunc() }
}

func (c *RootCLI) loadLog(cc *cobra.Command) (func(), error) {
	arg := cc.Flags().Lookup("log")
	if !arg.Changed {
		log.Info().Msg("SetLog.FollowGlobalSetting")
		return func() {}, nil
	}

	logFD, err := c.fs.OpenFile(c.logFile,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Error().Err(err).Msg("SetLog.OpenFile.Fail")
		return func() {}, err
	}

	barton.NewZerologConfig().
		SetGlobalPolicy().
		SetWriter(logFD).
		SetGlobalLogger()
	cleanupFunc := func() {
		logFD.Close()
	}
	return cleanupFunc, nil
}

func (c *RootCLI) loadConfig(cc *cobra.Command) (func(), error) {
	arg := cc.Flags().Lookup("config")
	if !arg.Changed { // It's default value.
		log.Info().Msg("ReadInConfig.Preset")
		err := c.v.ReadInConfig()
		if err != nil {
			log.Error().
				Err(err).
				Msg("ReadInConfig.Preset.Fail")
			return func() {}, err
		}
		return func() {}, nil
	}

	log.Info().Str("config", c.configFile).Msg("ReadConfig.Explicit")

	c.v.SetConfigFile(c.configFile)
	err := c.v.ReadInConfig()
	if err != nil {
		log.Error().
			Err(err).
			Str("config", c.configFile).
			Msg("ReadConfig.Fail")
		return func() {}, err
	}

	return func() {}, nil
}

// SetLocalViperPolicy method sets default viper configuration search file
// name and path. This API uses os.UserConfigDir() to get XDG compatible
// path. If it's working on a non-supported OS, it will fallback to
// a non-standard ~/.appName/config.yml
func (c *RootCLI) SetLocalViperPolicy() *RootCLI {
	// TODO Strictly speaking we should parse $XDG_CONFIG_HOME, but
	// it is a non-trivial work. Let's take it as is.
	//
	// Don't worry calling multiple times. Viper does the work of
	// checking duplicated search path.
	c.v.SetConfigName("config")
	c.v.SetConfigType("yml")
	configDir, err := os.UserConfigDir()
	if err != nil {
		// One possible case falling to here is
		// there's no $HOME folder defined.
		fallback := fmt.Sprintf(".%s", c.appName)
		log.Error().
			Err(err).
			Str("fallbackToPath", fallback).
			Msg("UserConfigDir.ParseXDGConfigPath")
		c.v.AddConfigPath(fallback)
		return c
	}

	// Always read local folder first, then global.
	c.v.AddConfigPath(fmt.Sprintf("%s/%s", configDir, c.appName))
	c.v.AddConfigPath(fmt.Sprintf("/etc/%s", c.appName))
	return c
}

// AddSubcommand methods binds a SubcommandBuilder object to RootCLI. It
// allows subcommand share configuration reading (via Viper) and file
// system abstraction via Afero. Internally, RootCLI uses a map to keep
// a reference of each subcommand.
func (c *RootCLI) AddSubcommand(child SubcommandBuilder) *RootCLI {
	configSection := fmt.Sprintf("%s.%s", c.appName, child.Name())
	child.Viper(c.v, configSection)
	child.AferoFS(c.fs)
	// Supposed I should write a log here but it will cause an
	// annoying result, because in command line scenario log file
	// initialization happens after AddSubcommand(), which always
	// write to stdout.
	// _, exists := c.subCommands[strings.ToLower(child.Name())]
	c.subCommands[strings.ToLower(child.Name())] = child
	return c
}
