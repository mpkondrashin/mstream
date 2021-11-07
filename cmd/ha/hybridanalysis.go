package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"
)

var (
	//	ErrTooBigFile    = errors.New("too big file size")
	ErrResponseError = errors.New("response error")
)

type HybridAnalysis struct {
	APIKey    string
	userAgent string
}

func NewHybridAnalysis(APIKey string) *HybridAnalysis {
	return &HybridAnalysis{
		APIKey:    APIKey,
		userAgent: "Falcon Sandbox",
	}
}

func (ha *HybridAnalysis) SetUserAgent(userAgent string) *HybridAnalysis {
	ha.userAgent = userAgent
	return ha
}

func (ha *HybridAnalysis) ListLatest() (*ListLatest, error) {
	client := &http.Client{}
	url := "https://www.hybrid-analysis.com/api/v2/feed/latest"
	//fmt.Printf("URL: %s\n", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	req.Header.Add("Api-Key", ha.APIKey)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", ha.userAgent)
	//req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()
	//fmt.Printf("Respond: %v", resp)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%w: %d", ErrResponseError, resp.StatusCode)
	}
	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll: %w", err)
	}
	//fmt.Printf("%v\n", string(jsonData))
	var data ListLatest
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w\n%s", err, string(jsonData))
	}
	log.Printf("Count: %d\n", data.Count)
	log.Printf("Status: %s\n", data.Status)
	return &data, nil
}

func (ha *HybridAnalysis) Report(jobID, reportType string) ([]byte, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://www.hybrid-analysis.com/api/v2/report/%s/report/%s", jobID, reportType)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Api-Key", ha.APIKey)
	//req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", ha.userAgent)
	//req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, err
	//fmt.Printf("%v\n", string(jsonData))
}

func (ha *HybridAnalysis) DownloadGzipSample(id string) (io.ReadCloser, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://www.hybrid-analysis.com/api/v2/report/%s/sample", id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Api-Key", ha.APIKey)
	req.Header.Add("Accept", "application/gzip")
	req.Header.Add("User-Agent", ha.userAgent)
	//req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp.Body.Close()
	return resp.Body, nil
}

func (ha *HybridAnalysis) DownloadSample(id string) (io.Reader, io.Closer, error) {
	g, err := ha.DownloadGzipSample(id)
	if err != nil {
		return nil, nil, err
	}
	r, err := gzip.NewReader(g)
	if err != nil {
		return nil, nil, err
	}
	return r, g, nil
}

func (ha *HybridAnalysis) __IterateReader(callback func(data *ListLatestData, r io.Reader) error,
	filter func(data *ListLatestData) bool) error {
	d, err := ha.ListLatest()
	if err != nil {
		return err
	}
	for i := range d.Data {
		each := &d.Data[i]
		if filter != nil && !filter(each) {
			continue
		}
		//fmt.Printf("%s\n", each.JobID)
		u, toClose, err := ha.DownloadSample(each.JobID)
		if err != nil {
			if errors.Is(err, gzip.ErrHeader) {
				log.Printf("Missing sample for %s", each.JobID)
				continue
			} else {
				return err
			}
		}
		err = callback(each, u)
		if err != nil {
			return err
		}
		toClose.Close()
	}
	return nil
}

func (ha *HybridAnalysis) IterateReader(callback func(data *ListLatestData, r io.Reader) error,
	filter func(data *ListLatestData) bool) error {
	d, err := ha.ListLatest()
	if err != nil {
		return err
	}
	eGroup := new(errgroup.Group)
	for i := range d.Data {
		each := &d.Data[i]
		if filter != nil && !filter(each) {
			continue
		}
		eGroup.Go(func() error {
			u, toClose, err := ha.DownloadSample(each.JobID)
			if err != nil {
				if errors.Is(err, gzip.ErrHeader) {
					log.Printf("Missing sample for %s", each.JobID)
					return nil
				} else {
					return err
				}
			}
			defer toClose.Close()
			return callback(each, u)
		})
	}
	return eGroup.Wait()
}

func (ha *HybridAnalysis) IterateFiles(
	callback func(data *ListLatestData, path string) error,
	filter func(data *ListLatestData) bool) error {
	dir, err := ioutil.TempDir("", "ha")
	if err != nil {
		return fmt.Errorf("ioutil.TempDir: %w", err)
	}
	//fmt.Printf("Temp folder: %s\n", dir)
	defer os.Remove(dir)
	return ha.IterateReader(func(data *ListLatestData, r io.Reader) error {
		fname := data.JobID + ".bin"
		path := filepath.Join(dir, fname)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if err != nil {
			return err
		}
		f.Close()
		newName := ""
		sha256, err := Sha256(path)
		if err != nil {
			return err
		}
		//fmt.Printf("Seek for %s\n", sha256)
		for _, each := range data.Processes {
			//fmt.Printf("each.Sha256: %s\n", each.Sha256)
			//fmt.Printf("each.Name: %s\n", each.Name)
			if each.Sha256 == sha256 {
				newName = each.Name
				break
			}
		}
		if newName == "" {
			for _, each := range data.Processes {
				if each.Name == "rundll32.exe" {
					// "C:\\steam_api64.dll",#1
					start := strings.Index(each.CommandLine, "\"")
					end := strings.LastIndex(each.CommandLine, "\"")
					if start == -1 || end == -1 {
						break
					}
					path := each.CommandLine[start+1 : end]
					backSlashPosition := strings.LastIndex(path, "\\")
					if backSlashPosition == -1 {
						break
					}
					newName = path[backSlashPosition+1:]
					break
				}
				if each.Name == "iexplore.exe" {
					// "command_line": "C:\\5302eb21e43123811ca5935e079c1e516c24ed7ea21113dd266.html"
					start := strings.Index(each.CommandLine, "\\")
					if start == -1 {
						newName = data.Sha1 + ".html"
						break
					}
					newName = each.CommandLine[start+1:]
					break
				}
			}
		}

		if newName != "" {
			newPath := filepath.Join(dir, newName)
			err := os.Rename(path, newPath)
			if err != nil {
				return err
			}
			path = newPath
		}
		return callback(data, path)
	}, filter)
}

type ListLatest struct {
	Count  int              `json:"count"`
	Status string           `json:"status"`
	Data   []ListLatestData `json:"data"`
}

type ListLatestData struct {
	JobID             string   `json:"job_id"`
	Md5               string   `json:"md5"`
	Sha1              string   `json:"sha1"`
	Sha256            string   `json:"sha256"`
	Interesting       bool     `json:"interesting"`
	AnalysisStartTime string   `json:"analysis_start_time"`
	ThreatScore       int      `json:"threat_score"`
	ThreatLevel       int      `json:"threat_level"`
	ThreatLevelHuman  string   `json:"threat_level_human"`
	Unknown           bool     `json:"unknown"`
	Domains           []string `json:"domains"`
	Hosts             []string `json:"hosts"`
	HostsGeolocation  []struct {
		IP        string `json:"ip"`
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
		Country   string `json:"country"`
	} `json:"hosts_geolocation"`
	EnvironmentID          int    `json:"environment_id"`
	EnvironmentDescription string `json:"environment_description"`
	SharedAnalysis         bool   `json:"shared_analysis"`
	Reliable               bool   `json:"reliable"`
	ReportURL              string `json:"report_url"`
	Processes              []struct {
		UID            string `json:"uid"`
		Name           string `json:"name"`
		NormalizedPath string `json:"normalized_path"`
		CommandLine    string `json:"command_line"`
		Sha256         string `json:"sha256"`
		Parentuid      string `json:"parentuid,omitempty"`
	} `json:"processes"`
	ExtractedFiles []struct {
		Name                    string   `json:"name"`
		FileSize                int      `json:"file_size"`
		Sha1                    string   `json:"sha1"`
		Sha256                  string   `json:"sha256"`
		Md5                     string   `json:"md5"`
		TypeTags                []string `json:"type_tags,omitempty"`
		Description             string   `json:"description"`
		RuntimeProcess          string   `json:"runtime_process"`
		ThreatLevel             int      `json:"threat_level"`
		ThreatLevelReadable     string   `json:"threat_level_readable"`
		AvMatched               int      `json:"av_matched,omitempty"`
		AvTotal                 int      `json:"av_total,omitempty"`
		FileAvailableToDownload bool     `json:"file_available_to_download"`
		FilePath                string   `json:"file_path,omitempty"`
	} `json:"extracted_files"`
	Ssdeep string `json:"ssdeep"`
}

func Sha256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
