package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	vt "github.com/VirusTotal/vt-go"

	"github.com/mpkondrashin/mstream/pkg/config"
)

const (
	name = "vtupload"
)

type VTUpload struct {
	conf    *config.VT
	scanner *vt.FileScanner
}

func main() {
	conf := &config.VT{}
	err := config.LoadFile(name+".yaml", conf)
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

	client := vt.NewClient(conf.VirusTotalAPIKey)
	scanner := client.NewFileScanner()

	uploader := &VTUpload{
		conf,
		scanner,
	}

	err = uploader.doScans(scanner)
	if err != nil {
		log.Fatalf("Scan Files error: %v\n", err)
		os.Exit(6)
	}
}

func (u *VTUpload) doScans(scanner *vt.FileScanner) error {
	nextTime := time.Now().Add(u.conf.Interval)
	for {
		err := u.doScanFolder()
		if err != nil {
			log.Print(err)
			fmt.Println(err)
		}
		sleep := time.Until(nextTime)
		nextTime = nextTime.Add(u.conf.Interval)
		log.Printf("Sleep %v", sleep)
		time.Sleep(sleep)
	}
}

func (u *VTUpload) doScanFolder() error {
	dirList, err := os.ReadDir(u.conf.TargetDir)
	if err != nil {
		return err
	}
	nextTime := time.Now().Add(u.conf.PauseBetweenSubmissions)
	for _, dirEntry := range dirList {
		dirPath := filepath.Join(u.conf.TargetDir, dirEntry.Name())
		shouldSleep, err := u.ProcessSample(dirPath)
		if err != nil {
			log.Print(err)
		}
		if !shouldSleep {
			continue
		}
		sleep := time.Until(nextTime)
		nextTime = nextTime.Add(u.conf.PauseBetweenSubmissions)
		log.Printf("Sleep between samples %v", sleep)
		time.Sleep(sleep)
	}

	return nil
}

func SampleFileName(folder string) (string, error) {
	dirList, err := os.ReadDir(folder)
	if err != nil {
		return "", err
	}
	for _, dirEntry := range dirList {
		filePath := filepath.Join(folder, dirEntry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		// Ignored files should be moved to separate function
		// '.*' mask is too simple
		// Need more to be ignored for Windows platform
		if dirEntry.Name()[0] == '.' {
			continue
		}
		return dirEntry.Name(), nil
	}
	return "", fmt.Errorf("%s: no sample found", folder)
}

func (u *VTUpload) ProcessSample(dirPath string) (sleep bool, err error) {
	sleep = false
	resultPath := filepath.Join(dirPath, "virustotalupload.json")
	_, err = os.Stat(resultPath)
	if err == nil {
		log.Printf("Already submitted: %s", dirPath)
		return
	}
	sampleFolder := filepath.Join(dirPath, "sample")
	sampleName, err := SampleFileName(sampleFolder)
	if err != nil {
		return
	}
	log.Printf("Submit sample: %s", sampleName)
	samplePath := filepath.Join(sampleFolder, sampleName)
	f, err := os.Open(samplePath)
	if err != nil {
		return
	}
	obj, err := u.scanner.ScanFile(f, nil)
	if err != nil {
		return
	}
	sleep = true
	json, err := obj.MarshalJSON()
	if err != nil {
		return
	}
	err = os.WriteFile(resultPath, json, 0700)
	return
}
