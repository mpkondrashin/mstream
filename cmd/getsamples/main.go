package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mpkondrashin/mstream/pkg/hybridanalysis"
)

func main() {
	conf := NewConfig()
	err := conf.LoadConfig()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	logF, err := os.OpenFile(conf.LogFilePath(), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0700)
	if err != nil {
		log.Fatalf("Log file error: %v\n", err)
		os.Exit(5)
	}
	defer logF.Close()
	log.SetOutput(logF)

	err = os.MkdirAll(conf.TargetDir, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		log.Print(err)
		fmt.Println(err)
		os.Exit(4)
	}

	samples := HASamples(conf)
	Interval := conf.Interval
	if Interval == 0 {
		Interval = 30 * time.Minute
	}
	nextTime := time.Now().Add(Interval)
	for {
		err = samples.Download(conf.TargetDir, nil)
		if err != nil {
			log.Printf("Download: %v", err)
			fmt.Printf("Download: %v", err)
		}
		sleep := time.Until(nextTime)
		nextTime = nextTime.Add(Interval)
		log.Printf("Sleep %v", sleep)
		time.Sleep(sleep)
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
	/*
		if len(conf.ExtList) > 0 {
			for _, each := range strings.Split(conf.ExtList, ",") {
				//	fmt.Printf("\"%s\" INCLUDE: %s\n", IncludeList, each)
				samples.SetExtension(each)
			}
		}*/
	return samples
}

/*

func FileSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil)), nil
}
*/
