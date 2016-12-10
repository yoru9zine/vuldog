package cmd

import (
	"log"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/yoru9zine/vuldog/vuldb"
	"github.com/yoru9zine/vuldog/vulweb"
)

var serverCmd = &cobra.Command{
	Use: "server",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := vuldb.New(dsn)
		if err != nil {
			log.Fatalf("database error: %s", err)
		}
		defer db.Close()
		hdlr := vulweb.NewHandler(db)
		s := &http.Server{
			Addr:           ":8080",
			Handler:        hdlr,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		log.Println("start server@8080")
		log.Fatal(s.ListenAndServe())
		//pp.Println(db.GetRecentCVE(10))
	},
}
