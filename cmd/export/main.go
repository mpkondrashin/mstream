package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mpkondrashin/mstream/pkg/virustotal"
)

var db = flag.String("db", "", "path to database file")
var output = flag.String("output", "", "output file name")

func main() {
	flag.Parse()
	if *output == "" || *db == "" {
		fmt.Println("Must pass both arguments (--db and --output).")
		os.Exit(0)
	}

	db, err := virustotal.NewDB(*db)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	err = db.CSV(f)
	if err != nil {
		panic(err)
	}
}
