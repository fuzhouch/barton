package cli

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// CMDConfig configures a root client command line interface.
// Though CMDConfig also implements NewCobraCMD() method, it does not
// implement Name() method, thus it's not considered as an
// implementation of CommandConfig interface. This is to ensure
// AddSubcommand() does not adds itself.
type CMDConfig struct {
	appName string
	Log     string
	Config  string

	enableLogOption    bool
	enableConfigOption bool
	Subcommands        map[string]CommandConfig
}

// NewCMDConfig creates a new command line configuratoin object
func NewCMDConfig(appName string) *CMDConfig {
	return &CMDConfig{
		appName: appName,
	}
}

// LogOption adds a --log command line option in root
// command line.
func (c *CMDConfig) LogOption() *CMDConfig {
	c.enableLogOption = true
	return c
}

// ConfigOption adds a --config command line option in root
// command line.
func (c *CMDConfig) ConfigOption() *CMDConfig {
	c.enableConfigOption = true
	return c
}

// AddSubcommand adds a subcommand object to root. If a subcommand
// object with same name already exists, the previous one is
// overwritten.
func (c *CMDConfig) AddSubcommand(sc CommandConfig) *CMDConfig {
	if _, found := c.Subcommands[strings.ToLower(sc.Name())]; found {
		log.Warn().Str("name", sc.Name()).Msg("OverwriteCMD")
	}
	c.Subcommands[sc.Name()] = sc
	return c
}

// SubcommandExists checks whether a given subcommand object has been
// added to root command. If it returns yes, developer needs to be
// careful that existing one can be overwritten when adding this new
// subcommand.
func (c *CMDConfig) SubcommandExists(scName string) bool {
	_, found := c.Subcommands[strings.ToLower(scName)]
	return found
}

// NewCobraCMD creates a Cobra's cobra.Command object that represents
// root command line interface.
func (c *CMDConfig) NewCobraCMD() *cobra.Command {
	cmd := &cobra.Command{}

	for _, s := range c.Subcommands {
		subCmd := s.NewCobraCMD()
		cmd.AddCommand(subCmd)
	}
	return cmd
}
