package cli

import (
	"testing"

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
	assert.NotEqual(t, v, login.v)

	cmd := root.NewCobraE(nil)
	cmd.SetArgs([]string{"login", "-u", "1", "-p", "2"})
	err := cmd.Execute()
	assert.NotNil(t, err) // Expected: We don't have a valid URL.
	assert.NotNil(t, v.Get("test-app.login"))
	assert.Nil(t, v.Get("test-app.login.username"))
	assert.Nil(t, v.Get("test-app.login.token"))
	// All values are empty. But WE DON'T CRASH!
}
