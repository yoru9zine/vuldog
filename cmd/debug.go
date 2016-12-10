package cmd

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"
	cpe "github.com/umisama/go-cpe"
	"github.com/yoru9zine/vuldog"
	"github.com/yoru9zine/vuldog/vuldb"
)

var debugCmd = &cobra.Command{
	Use: "debug",
}

var debugCPEListCmd = &cobra.Command{
	Use: "cpelist",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("required xml file of cpe-dictionary")
		}
		b, err := ioutil.ReadFile(args[0])
		if err != nil {
			log.Fatalf("failed to read file %s: %s", args[0], err)
		}
		var cpeList vuldog.CPEList
		if err := xml.Unmarshal(b, &cpeList); err != nil {
			log.Fatalf("failed to load xml %s: %s", args[0], err)
		}
		fmt.Println(cpeList.ProductName)
		fmt.Println(cpeList.ProductVersion)
		fmt.Println(cpeList.SchemaVersion)
		fmt.Println(cpeList.Timestamp)
		for _, item := range cpeList.Items {
			_, err := cpe.NewItemFromUri(item.Name)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", item.Name)
		}
	},
}

var debugNVDListCmd = &cobra.Command{
	Use: "nvdlist",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("required xml file of nvd")
		}
		b, err := ioutil.ReadFile(args[0])
		if err != nil {
			log.Fatalf("failed to read file %s: %s", args[0], err)
		}
		var nvd vuldog.NVD
		if err := xml.Unmarshal(b, &nvd); err != nil {
			log.Fatalf("failed to load xml %s: %s", args[0], err)
		}
		for _, entry := range nvd.Entries {
			pp.Println(entry)
		}
	},
}

var debugCVECmd = &cobra.Command{
	Use: "cve",
}

var debugCVEAllCmd = &cobra.Command{
	Use: "all",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := vuldb.New(dsn)
		if err != nil {
			log.Fatalf("database error: %s", err)
		}
		defer db.Close()
		pp.Println(db.GetRecentCVE(10))
	},
}

func init() {
	debugCVECmd.AddCommand(debugCVEAllCmd)
	debugCmd.AddCommand(debugCPEListCmd)
	debugCmd.AddCommand(debugNVDListCmd)
	debugCmd.AddCommand(debugCVECmd)
}
