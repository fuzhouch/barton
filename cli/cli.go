package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// CMDConfig configures a root client command line interface.
type CMDConfig struct {
	appName        string
	subcommands    map[string]CommandConfig
	configFileName string
	LogFileName    string
}

// NewCMDConfig creates a new command line configuration object. It
// takes configurations and create an cobra.Command object.
func NewCMDConfig(appName string) *CMDConfig {
	return &CMDConfig{
		appName:     appName,
		subcommands: make(map[string]CommandConfig),
	}
}

// AddSubcommand adds a subcommand object to root. If a subcommand
// object with same name already exists, the previous one is
// overwritten.
func (c *CMDConfig) AddSubcommand(sc CommandConfig) *CMDConfig {
	if _, found := c.subcommands[strings.ToLower(sc.Name())]; found {
		log.Warn().Str("name", sc.Name()).Msg("OverwriteCMD")
	}
	c.subcommands[sc.Name()] = sc
	return c
}

// SubcommandExists checks whether a given subcommand object has been
// added to root command. If it returns yes, developer needs to be
// careful that existing one can be overwritten when adding this new
// subcommand.
func (c *CMDConfig) SubcommandExists(scName string) bool {
	_, found := c.subcommands[strings.ToLower(scName)]
	return found
}

// Name method returns appname of root command line processor. It's
// implementation of CommandConfig interface.
func (c *CMDConfig) Name() string {
	return c.appName
}

type CobraRunEFunc = func(*cobra.Command, []string) error

// NewCobraCMD creates a Cobra's cobra.Command object that represents
// root command line interface.
func (c *CMDConfig) NewCobraCMD(run CobraRunEFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:   c.appName,
		Short: fmt.Sprintf("CLI for %s", c.appName),
		Long:  fmt.Sprintf("CLI for %s", c.appName),
		RunE: func(cc *cobra.Command, args []string) error {
			logCleanup, err := c.parseLog()
			if err != nil {
				return err
			}
			defer logCleanup()

			configCleanup, err := c.parseConfig()
			if err != nil {
				return err
			}
			defer configCleanup()

			if run != nil {
				return run(cc, args)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(
		&c.configFileName,
		"config",
		"c",
		"",
		"Config file to read content.")
	cmd.Flags().StringVarP(
		&c.LogFileName,
		"log",
		"l",
		"",
		"Log file to contain log. If omitted, writes to stdout.")

	// XXX Please always keep in mind that the two root options,
	// --config and --log should NEVER be bound to any parameters.
	//
	// It's obvious that --config must be read from command line
	// explicitly: there's no way for us to read configuration file
	// name from a configuration body. Meanwhile, --log option is a
	// mandatory option to read from command line because I don't
	// want to introduce a dependency between logging and
	// configuration file. Thus, an error when reading confiugration
	// file can always be logged.

	// Though it may be counter-intuitive, login subcommand is NOT
	// always added by default. Remember that our API can be created
	// without authentication? This is to support it.
	for _, s := range c.subcommands {
		subCmd := s.NewCobraCMD()
		cmd.AddCommand(subCmd)
		BindViperFlags(c.appName, subCmd.Name(), subCmd)
	}
	return cmd
}

func (c *CMDConfig) parseLog() (func(), error) {
	return func() {}, nil
}

func (c *CMDConfig) parseConfig() (func(), error) {
	return func() {}, nil
}

// BindViperFlags binds options of given cobra.Command command to viper.
// Each option binds to a name with pattern
// "cmdName.subCmdName.optionName". It's a helper function to allow
// Barton's root command binds options of sub command, but also useable
// for general use.
func BindViperFlags(cmdName, subCmdName string, subCmd *cobra.Command) {
	subCmd.Flags().VisitAll(func(pf *pflag.Flag) {
		prefix := fmt.Sprintf("%s.%s.%s",
			cmdName, subCmdName, pf.Name)
		viper.BindPFlag(prefix, pf)
	})
}
