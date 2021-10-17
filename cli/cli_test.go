package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fuzhouch/barton"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestDefaultClientCreated creates a default command line client,
// verify the default settings.
func TestDefaultClientCreated(t *testing.T) {
	cfg := NewRootCLI("test-app")
	assert.Equal(t, "test-app", cfg.appName)
}

// TestRunWithExplicitConfigFileInOptions verifies an explicit
// configuration file specified in command line can be opened and read.
func TestRunWithExplicitConfigFileInOptions(t *testing.T) {
	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./test.yml", []byte("key: config"), 0644)
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{"--config", "./test.yml"})
	root.Execute()
	value := v.GetString("key")
	assert.Equal(t, "config", value)
}

// TestDefaultConfigFileLocalConfigFirst verifies default configuration
// file reading order. It should be .config folder first, then go to
// file under global /etc folder.
func TestDefaultConfigFileLocalConfigFirst(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/test-app/config.yml",
		[]byte("location: etc"), 0644)
	assert.Nil(t, err)
	configDir, err := os.UserConfigDir()
	assert.Nil(t, err)
	localDir := fmt.Sprintf("%s/test-app/config.yml", configDir)
	err = afero.WriteFile(fs, localDir,
		[]byte("location: .config"), 0644)
	assert.Nil(t, err)

	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{})
	root.Execute()
	value := v.GetString("location")
	assert.Equal(t, ".config", value)
}

// TestDefaultConfigFileFallbackToEtc verifies default configuration
// file reading order. If per-user configuration is not defined,
// fallback to filer under global /etc folder.
func TestDefaultConfigFileFallbackToEtc(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/test-app/config.yml",
		[]byte("location: etc"), 0644)
	assert.Nil(t, err)

	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{})
	root.Execute()
	value := v.GetString("location")
	assert.Equal(t, "etc", value)
}

// TestUserConfigDirReturnError verifies code returns a default,
// non-standard path, when os.UserConfigDir() can't return a correct
// directory.
func TestUserConfigDirReturnError(t *testing.T) {
	// IMPORTANT This unit test covers windows, Mac and Unix. It may
	// fail on other systems. Basic idea is we intentionally build a
	// bad environment variable to trigger error from
	// os.UserConfigDir().
	home := os.Getenv("HOME")
	plan9Home := os.Getenv("home")
	appDir := os.Getenv("AppData")
	defer os.Setenv("HOME", home)
	defer os.Setenv("home", plan9Home)
	defer os.Setenv("AppData", appDir)

	// Now, trigger an error
	os.Setenv("HOME", "")
	os.Setenv("AppDir", "")
	os.Setenv("home", "")

	// A behavior of viper is to convert given relative path to
	// absolute.
	wd, err := os.Getwd()
	assert.Nil(t, err)
	fallback := fmt.Sprintf("%s/.test-app/config.yml", wd)

	fs := afero.NewMemMapFs()
	err = afero.WriteFile(fs, fallback,
		[]byte("location: non-standard"), 0644)
	assert.Nil(t, err)
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{})
	root.Execute()
	assert.Equal(t, fallback, v.ConfigFileUsed())
	value := v.GetString("location")
	assert.Equal(t, "non-standard", value)
}

// TestDefaultConfigReadFailOnNoFileExist verifies default configuration
// file reading returns error, when none of given path contains
// configuration file.
func TestDefaultConfigReadFileOnNoFileExist(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root.SetArgs([]string{})
	err := root.Execute()
	assert.NotNil(t, err)
	out := b.String()
	assert.True(t, strings.Contains(out, "ReadInConfig.Preset.Fail"))
	var ee viper.ConfigFileNotFoundError
	assert.True(t, errors.As(err, &ee))
}

// TestExplicitConfigReadFail verifies explicit configuration file
// reading returns error, when none of given path contains configuration
// file.
func TestExplicitConfigReadFail(t *testing.T) {
	fs := afero.NewMemMapFs()
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root.SetArgs([]string{"-c", "file-not-found.yml"})
	err := root.Execute()
	assert.NotNil(t, err)
	out := b.String()
	assert.True(t, strings.Contains(out, "ReadConfig.Explicit"))
	assert.True(t, strings.Contains(out, "ReadConfig.Fail"))
}

// TestExplicitConfigReadContentFail verifies explicit configuration
// file reading returns error, when file exists with corrupted content.
func TestExplicitConfigReadContentFail(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "bad-content.yml",
		[]byte("=location=etc"), 0644)
	assert.Nil(t, err)
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root.SetArgs([]string{"-c", "bad-content.yml"})
	err = root.Execute()
	assert.NotNil(t, err)
	out := b.String()
	assert.True(t, strings.Contains(out, "ReadConfig.Explicit"))
	assert.True(t, strings.Contains(out, "ReadConfig.Fail"))
}

// TestExplicitLogCannotOpenReturnError verifies error returned when log
// file can't be opened. This happens only when log path is specified
// explicitly.
func TestExplicitLogCannotOpenReturnError(t *testing.T) {
	mem := afero.NewMemMapFs()
	fs := afero.NewReadOnlyFs(mem)

	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root.SetArgs([]string{"--log", "cannot-write.log"})
	err := root.Execute()
	assert.NotNil(t, err)
	out := b.String()
	assert.True(t, strings.Contains(out, "SetLog.OpenFile.Fail"))
}

// TestExplicitLogOpenOnNotExist verifies an explicit log path can be
// craeted automatically.
func TestExplicitLogOpenOnNotExist(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/test-app/config.yml",
		[]byte("location: etc"), 0644)
	assert.Nil(t, err)

	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{"--log", "open-by-default.log"})
	err = root.Execute()
	assert.Nil(t, err)
	logFileExists, err := afero.Exists(fs, "open-by-default.log")
	assert.Nil(t, err)
	assert.True(t, logFileExists)
}

// TestDefaultLogFollowGlobalSetting verifies an implicit log setting
// follows global settings.
func TestDefaultLogFollowGlobalSetting(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/test-app/config.yml",
		[]byte("location: etc"), 0644)
	assert.Nil(t, err)

	v := viper.New()
	v.SetFs(fs)

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	defer cleanupFunc()

	root.SetArgs([]string{""})
	err = root.Execute()
	assert.Nil(t, err)

	out := b.String()
	assert.True(t, strings.Contains(out, "SetLog.FollowGlobalSetting"))
}

// TestExplicitRunEFunctionIsCalled verifies a given RunE function is
// called when passed to NewCobraE() method.
func TestExplicitRunEFunctionIsCalled(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/test-app/config.yml",
		[]byte("location: etc"), 0644)
	assert.Nil(t, err)

	v := viper.New()
	v.SetFs(fs)

	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(func(cc *cobra.Command, args []string) error {
			log.Info().Msg("InRunE")
			return nil
		})
	defer cleanupFunc()

	root.SetArgs([]string{""})
	err = root.Execute()
	assert.Nil(t, err)

	out := b.String()
	assert.True(t, strings.Contains(out, "InRunE"))
}

// TestLogCleanupFuncCalled verifies a cleanup function with proper log
// and config cleanup step is called when cmd.Execute() is invoked.
func TestLogCleanupFuncCalled(t *testing.T) {
	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./test.yml", []byte("key: config"), 0644)
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	root.SetArgs([]string{"--config", "./test.yml"})

	root.Execute()

	value := v.GetString("key")
	assert.Equal(t, "config", value)

	cleanupFunc()

	content := b.String()
	fmt.Printf("%s\n", content)
	assert.True(t, strings.Contains(content, "Cleanup.Bye"))
}

// TestLogDefaultCleanupFuncCalled verifies a default, no-action
// cleanup function is called if there's no cmd.Execute() invoked.
func TestLogDefaultCleanupFuncCalled(t *testing.T) {
	b := bytes.NewBufferString("")
	barton.NewZerologConfig().SetWriter(b).SetGlobalLogger()

	fs := afero.NewMemMapFs()
	afero.WriteFile(fs, "./test.yml", []byte("key: config"), 0644)
	v := viper.New()
	v.SetFs(fs)

	root, cleanupFunc := NewRootCLI("test-app").
		AferoFS(fs).
		Viper(v).
		SetLocalViperPolicy().
		NewCobraE(nil)
	root.SetArgs([]string{"--config", "./test.yml"})

	cleanupFunc()

	content := b.String()
	fmt.Printf("%s\n", content)
	assert.True(t, strings.Contains(content, "Cleanup.NoAction.Bye"))
}
