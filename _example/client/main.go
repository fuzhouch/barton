package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/fuzhouch/barton"
	"github.com/fuzhouch/barton/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	// Setup Zerolog
	zc := barton.NewZerologConfig().UseUTCTime()
	zc.SetGlobalPolicy().SetOffGlobalLogger()

	login := cli.NewHTTPBasicLogin("login", "http://127.0.0.1:8080/login")

	rootCLI, cleanup := cli.NewRootCLI("testcli").
		SetLocalViperPolicy().
		AddSubcommand(login).
		NewCobraE(func(c *cobra.Command, args []string) error {
			// IMPORTANT This is an example to show usage of Barton
			// APIs. For showing the main path it skips all error
			// handling logic. This is bad practice for production
			// use. Please properly handle errors instead of copy
			// and paste code blindly.
			token := viper.GetString("testcli.login.token")
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/v1/hello", nil)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			cli := &http.Client{}
			resp, _ := cli.Do(req)
			defer resp.Body.Close()

			answer, _ := ioutil.ReadAll(resp.Body)
			fmt.Printf("Answer from server: %s\n", answer)

			return nil
		})
	defer cleanup()

	err := rootCLI.Execute()
	if err != nil {
		fmt.Printf("Error on execution: %s.", err.Error())
		os.Exit(1)
	}
}
