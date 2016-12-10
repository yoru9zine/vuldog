package main

import (
	"fmt"
	"os"

	"github.com/yoru9zine/vuldog/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
