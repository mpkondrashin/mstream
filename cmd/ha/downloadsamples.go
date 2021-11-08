package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mpkondrashin/mstream/pkg/hybridanalysis"
)

type DownloadSamples struct {
	ha *hybridanalysis.HybridAnalysis
	//	tagetFolder          string
	skipList             []string
	includeList          []string
	threatLevelThreshold int
}

func NewDownloadSamples(ha *hybridanalysis.HybridAnalysis) *DownloadSamples {
	return &DownloadSamples{
		ha: ha,
		//	tagetFolder:          tagetFolder,
		threatLevelThreshold: 2,
	}
}

func (ds *DownloadSamples) SetSkip(keyword string) *DownloadSamples {
	ds.skipList = append(ds.skipList, keyword)
	return ds
}

func (ds *DownloadSamples) SetInclude(keyword string) *DownloadSamples {
	ds.includeList = append(ds.includeList, keyword)
	return ds
}

func (ds *DownloadSamples) SetThreatLevelThreshold(threatLevelThreshold int) *DownloadSamples {
	ds.threatLevelThreshold = threatLevelThreshold
	return ds
}

func (ds *DownloadSamples) Download(targetFolder string) error {
	return ds.ha.IterateFiles(
		func(data *hybridanalysis.ListLatestData, path string) error {
			folderName := data.Sha1
			folderPath := filepath.Join(targetFolder, folderName)
			err := os.Mkdir(folderPath, 0700)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			repName := fmt.Sprintf("%s.json", data.Sha1)
			repPath := filepath.Join(folderPath, repName)
			fileName := filepath.Base(path)
			newPath := filepath.Join(folderPath, fileName)
			err = os.Rename(path, newPath)
			if err != nil {
				return err
			}
			log.Printf("New sample: %s", fileName)
			repFile, err := os.Create(repPath)
			if err != nil {
				return err
			}
			defer repFile.Close()
			s, _ := json.MarshalIndent(data, "", "\t")
			_, err = repFile.Write(s)
			if err != nil {
				return err
			}
			return nil
		},
		func(data *hybridanalysis.ListLatestData) bool {
			//repName := fmt.Sprintf("%s.txt", data.JobID)
			repPath := filepath.Join(targetFolder, data.Sha1)
			_, err := os.Stat(repPath)
			if err == nil {
				log.Printf("%s: already have it", repPath)
				return false
			}
			if data.ThreatLevel < ds.threatLevelThreshold {
				log.Printf("%d: skip low threat level", data.ThreatLevel)
				return false
			}
			include := true
			for _, keyword := range ds.includeList {
				include = false
				if strings.Contains(data.EnvironmentDescription, keyword) {
					log.Printf("%s: include as \"%s\" found", data.EnvironmentDescription, keyword)
					include = true
					break
				}
			}
			if !include {
				return false
			}
			for _, keyword := range ds.skipList {
				if strings.Contains(data.EnvironmentDescription, keyword) {
					//fmt.Println("Skip Linux")
					log.Printf("%s: skip as \"%s\" found", data.EnvironmentDescription, keyword)
					return false
				}
			}
			return true
		})
}
