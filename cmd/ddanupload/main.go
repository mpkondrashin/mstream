package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mpkondrashin/ddan"
	"github.com/mpkondrashin/mstream/pkg/config"
)

const (
	name = "ddan"
)

type DDAnUpload struct {
	conf     *config.DDAn
	analyzer *ddan.Client
}

func main() {
	conf := &config.DDAn{}
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

	log.Printf("%s Started", name)

	url, err := url.Parse(conf.Hostname)
	if err != nil {
		panic(err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	client := ddan.NewClient(conf.ProductName, hostname).
		SetAnalyzer(url, conf.APIKey, conf.IgnoreTLSError).
		SetSource(conf.SourceID, conf.SourceName).
		SetUUID(conf.ClientUUID)

	err = client.TestConnection()
	if err != nil {
		log.Fatalf("Test connection failed: %v", err)
		os.Exit(7)
	}
	log.Print("Test connection: passed")

	err = client.Register()
	if err != nil {
		log.Fatalf("Register error: %v", err)
		os.Exit(8)
	}
	log.Print("Registered successfully")

	uploader := &DDAnUpload{
		conf,
		client,
	}

	err = uploader.doScans()
	if err != nil {
		log.Fatalf("Scan Files error: %v", err)
		os.Exit(6)
	}
}

func (u *DDAnUpload) doScans() error {
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

func (u *DDAnUpload) doScanFolder() error {
	dirList, err := os.ReadDir(u.conf.TargetDir)
	if err != nil {
		return err
	}
	for _, dirEntry := range dirList {
		dirPath := filepath.Join(u.conf.TargetDir, dirEntry.Name())
		err := u.ProcessSample(dirPath)
		if err != nil {
			log.Print(err)
		}
	}
	return nil
}

func (u *DDAnUpload) ProcessSample(dirPath string) error {
	ddanUploadFileName := "ddanupload.json"
	ddanUploadFilePath := filepath.Join(dirPath, ddanUploadFileName)
	_, err := os.Stat(ddanUploadFilePath)
	if err == nil {
		log.Printf("Already submitted: %s", dirPath)
		return nil
	}

	sha1FileName := "sha1.txt"
	sha1FilePath := filepath.Join(dirPath, sha1FileName)
	sha1, err := os.ReadFile(sha1FilePath)
	if err != nil {
		return err
	}

	sha1List, err := u.analyzer.CheckDuplicateSample([]string{string(sha1)}, 0)
	if err != nil {
		return err
	}
	if len(sha1List) > 0 {
		log.Printf("%s: Already submitted", dirPath)
		return nil
	}

	sampleFolder := filepath.Join(dirPath, "sample")
	sampleName, err := SampleFileName(sampleFolder)
	if err != nil {
		return err
	}
	log.Printf("Submit sample: %s", sampleName)
	samplePath := filepath.Join(sampleFolder, sampleName)

	err = u.analyzer.UploadSample(samplePath, string(sha1))
	if err != nil {
		return err
	}

	f, err := os.Create(ddanUploadFilePath)
	if err != nil {
		return err
	}
	return f.Close()
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
