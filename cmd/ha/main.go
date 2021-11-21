package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/mpkondrashin/mstream/pkg/hybridanalysis"
	"github.com/mpkondrashin/mstream/pkg/virustotal"
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

	client := vt.NewClient(conf.VirusTotalAPIKey)
	scanner := client.NewFileScanner()

	samples := HASamples(conf)
	pathChan := make(chan string)
	go func() {
		Interval := 30 * time.Minute
		nextTime := time.Now().Add(Interval)
		for {
			err = samples.Download(conf.TargetDir, pathChan)
			if err != nil {
				log.Print(err)
				//fmt.Println(err)
				os.Exit(5)
			}
			sleep := time.Until(nextTime)
			nextTime = nextTime.Add(Interval)
			log.Printf("Sleep %v", sleep)
			time.Sleep(sleep)
		}
	}()
	db, err := virustotal.NewDB(conf.DataBase)
	if err != nil {
		panic(err)
	}
	for {
		path, ok := <-pathChan
		if !ok {
			break
		}
		log.Printf("Sample: %s", path)
		f, err := os.Open(path)
		if err != nil {
			log.Print(err)
			continue
		}
		obj, err := scanner.ScanFile(f, nil)
		if err != nil {
			log.Print(err)
			continue
		}
		f.Close()
		json, err := obj.MarshalJSON()
		if err != nil {
			log.Print(err)
			continue
		}
		err = os.WriteFile(path+".json", json, 0700)
		if err != nil {
			log.Print(err)
			continue
		}
		time.Sleep(10 * time.Minute)
		sha256, err := FileSHA256(path)
		if err != nil {
			log.Print(err)
			continue
		}
		err = virustotal.StoreResult(client, db, sha256)
		if err != nil {
			log.Print(err)
			continue
		}

	}
}

func HASamples(conf *Config) *hybridanalysis.Samples {
	ha := hybridanalysis.New(conf.HybridAnalysisAPIKey)
	samples := hybridanalysis.NewSamples(ha).SetThreatLevelThreshold(conf.ThreatLevelThreshold)
	if len(conf.SkipList) > 0 {
		for _, each := range strings.Split(conf.SkipList, ",") {
			samples.SetSkip(each)
		}
	}
	if len(conf.IncludeList) > 0 {
		for _, each := range strings.Split(conf.IncludeList, ",") {
			//	fmt.Printf("\"%s\" INCLUDE: %s\n", IncludeList, each)
			samples.SetInclude(each)
		}
	}
	if len(conf.ExtList) > 0 {
		for _, each := range strings.Split(conf.ExtList, ",") {
			//	fmt.Printf("\"%s\" INCLUDE: %s\n", IncludeList, each)
			samples.SetExtension(each)
		}
	}
	return samples
}

func FileSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil)), nil
}
