package cmd

import "github.com/spf13/cobra"

var RootCmd = &cobra.Command{
	Use: "Vuldog",
}

func init() {
	RootCmd.AddCommand(dbCmd)
	RootCmd.AddCommand(debugCmd)
	RootCmd.AddCommand(serverCmd)
}
