package main

import (
	"errors"
	"flag"
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

var (
	HybridAnalysisAPIKey string = ""
	ThreatLevelThreshold int    = 0
	SkipList             string = ""
	IncludeList          string = ""
	TargetDir            string = ""
)

//	maxFileSize          = 100000000

func ParseArgs() {
	flag.StringVar(&HybridAnalysisAPIKey, "hakey", "", "Hybrid Analysis API key")
	flag.StringVar(&TargetDir, "output", "", "Target folder")
	flag.IntVar(&ThreatLevelThreshold, "level", 2, "Threat level threshold")
	flag.StringVar(&SkipList, "skip", "", "Coma separated list of platform keywords to skip")
	flag.StringVar(&SkipList, "include", "", "Coma separated list of platform keywords to include")
	flag.Parse()
	if TargetDir == "" {
		fmt.Println("No output folder provided")
		os.Exit(1)
	}
	if HybridAnalysisAPIKey == "" {
		fmt.Println("No Hybrid Analysis API key provided")
		os.Exit(2)
	}
	if ThreatLevelThreshold < 0 || ThreatLevelThreshold > 2 {
		fmt.Println("Wrong threat level threshold value")
		os.Exit(3)
	}
}

func main() {
	ParseArgs()
	err := os.MkdirAll(TargetDir, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Print(err)
		fmt.Println(err)
		os.Exit(4)
	}
	ha := NewHybridAnalysis(HybridAnalysisAPIKey)
	ds := NewDownloadSamples(ha).SetThreatLevelThreshold(ThreatLevelThreshold)
	if len(SkipList) > 0 {
		for _, each := range strings.Split(SkipList, ",") {
			ds.SetSkip(each)
		}
	}
	if len(IncludeList) > 0 {
		for _, each := range strings.Split(IncludeList, ",") {
			//	fmt.Printf("\"%s\" INCLUDE: %s\n", IncludeList, each)
			ds.SetInclude(each)
		}
	}
	err = ds.Download(TargetDir)
	if err != nil {
		log.Print(err)
		fmt.Println(err)
		os.Exit(5)
	}
}
