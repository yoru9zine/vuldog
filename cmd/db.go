package cmd

import (
	"encoding/xml"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	"github.com/yoru9zine/vuldog"
	"github.com/yoru9zine/vuldog/vuldb"
)

var dbCmd = &cobra.Command{
	Use: "db",
}
var dsn = "postgres://postgres:mysecretpassword@localhost:5432/?sslmode=disable"

var dbCreateCmd = &cobra.Command{
	Use: "create",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := vuldb.New(dsn)
		if err != nil {
			log.Fatalf("database error: %s", err)
		}
		defer db.Close()
		if err := db.Create(); err != nil {
			log.Fatalf("failed to create database: %s", err)
		}
		log.Printf("Database created")
	},
}

var dbDropCmd = &cobra.Command{
	Use: "drop",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := vuldb.New(dsn)
		if err != nil {
			log.Printf("database error: %s", err)
		}
		defer db.Close()
		db.Drop()
		log.Printf("Database dropped")
	},
}

var dbStoreCmd = &cobra.Command{
	Use: "store",
}

var dbStoreNVDCmd = &cobra.Command{
	Use: "nvd",
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

		db, err := vuldb.New(dsn)
		if err != nil {
			log.Fatalf("database error: %s", err)
		}
		defer db.Close()
		if err := db.InsertNVD(&nvd); err != nil {
			log.Fatalf("failed to insert NVD: %s", err)
		}
	},
}

var dbInitCmd = &cobra.Command{
	Use: "init",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("xml directory required")
		}

		rootdir := args[0]
		nvddir := rootdir + "/nvd/"
		nvdFiles, err := ls(nvddir)
		if err != nil {
			log.Fatalf("failed to get cpe files from `%s`: %s", nvddir, err)
		}

		dbDropCmd.Run(cmd, nil)
		dbCreateCmd.Run(cmd, nil)

		for _, nvdFile := range nvdFiles {
			dbStoreNVDCmd.Run(cmd, []string{nvddir + nvdFile})
			log.Printf("nvd %s stored\n", nvdFile)
		}
	},
}

func ls(path string) ([]string, error) {
	fis, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	files := make([]string, len(fis))
	for i, fi := range fis {
		files[i] = fi.Name()
	}
	return files, nil
}

func init() {
	dbCmd.AddCommand(dbCreateCmd)
	dbCmd.AddCommand(dbDropCmd)
	dbCmd.AddCommand(dbStoreCmd)
	dbCmd.AddCommand(dbInitCmd)
	dbStoreCmd.AddCommand(dbStoreNVDCmd)
}
