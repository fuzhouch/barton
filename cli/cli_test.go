package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// Add setup() and shutdown() function to allow we create files in
// memory. This makes our test on cli package possible.
var fsForTest afero.Fs

func setup() {
	fsForTest = afero.NewMemMapFs()
	viper.SetFs(fsForTest)
}

func shutdown() {
}

// TestDefaultClientCreated creates a default command line client,
// verify the default settings.
func TestDefaultClientCreated(t *testing.T) {
	cfg := NewCMDConfig("test-app")
	assert.Equal(t, "test-app", cfg.appName)
}

func TestAddLoginSubcommand(t *testing.T) {
	sub := NewHTTPBasicLoginConfig("login", "http://127.0.0.1")
	root := NewCMDConfig("test-app").AddSubcommand(sub).NewCobraCMD(nil)

	b := bytes.NewBufferString("")
	root.SetOut(b)
	root.SetArgs([]string{"login", "--help"})

	root.Execute()
	out := b.String()
	assert.True(t, strings.Contains(out,
		"Login command with HTTP basic login"))
}

func TestConfigFileCreated(t *testing.T) {
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}
