package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

/*
cat get.sh
curl -X 'GET' \
  'https://www.hybrid-analysis.com/api/v2/report/6180e5d83806636f4260596e/sample' \
  -H 'api-key: 43pl4yirf963ca05dnb6bz7k02fe385ep5ju1xpga3fc7f43nma5p9o92e2a729c' \
  -H 'accept: application/gzip' \
  -H 'user-agent: Falcon Sandbox' \
  --output a.bin
*/

func main() {
	conf := NewConfig()
	err := conf.ParseAll("mstream.yaml")
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	if conf.Log != "" {
		logF, err := os.OpenFile(conf.Log, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0700)
		if err != nil {
			log.Fatalf("Log file error: %v\n", err)
			os.Exit(5)
		}
		defer logF.Close()
		log.SetOutput(logF)
	}
	err = os.MkdirAll(conf.TargetDir, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Print(err)
		fmt.Println(err)
		os.Exit(4)
	}
	ha := NewHybridAnalysis(conf.HybridAnalysisAPIKey)
	ds := NewDownloadSamples(ha).SetThreatLevelThreshold(conf.ThreatLevelThreshold)
	if len(conf.SkipList) > 0 {
		for _, each := range strings.Split(conf.SkipList, ",") {
			ds.SetSkip(each)
		}
	}
	if len(conf.IncludeList) > 0 {
		for _, each := range strings.Split(conf.IncludeList, ",") {
			//	fmt.Printf("\"%s\" INCLUDE: %s\n", IncludeList, each)
			ds.SetInclude(each)
		}
	}
	err = ds.Download(conf.TargetDir)
	if err != nil {
		log.Print(err)
		//fmt.Println(err)
		os.Exit(5)
	}
}
