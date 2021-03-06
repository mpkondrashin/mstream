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

/*
Created

Virus Total

Hybrid Analysis

Us

Created

Hybrid Analysis

Us

Virus Total


*/

//const timeLayout = "2006-01-02 15:04:05" // -0700 MST"
const name = "vtanalysis"

type VTAnalysis struct {
	conf   *config.VT
	client *vt.Client
}

func main() {
	conf := &config.VT{}
	err := config.LoadFile(name+".yaml", conf)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	defer conf.SetupLogging().Close()

	client := vt.NewClient(conf.VirusTotalAPIKey)

	analysis := &VTAnalysis{
		conf,
		client,
	}
	err = analysis.doScans()
	if err != nil {
		log.Fatalf("Download analysis result Files error: %v\n", err)
		os.Exit(6)
	}
}

func (a *VTAnalysis) doScans() error {
	nextTime := time.Now().Add(a.conf.Interval)
	for {
		err := a.doScanFolder()
		if err != nil {
			log.Print(err)
			fmt.Println(err)
		}
		sleep := time.Until(nextTime)
		nextTime = nextTime.Add(a.conf.Interval)
		log.Printf("Sleep %v", sleep)
		time.Sleep(sleep)
	}
}

func (a *VTAnalysis) doScanFolder() error {
	dirList, err := os.ReadDir(a.conf.TargetDir)
	if err != nil {
		return err
	}
	nextTime := time.Now().Add(a.conf.PauseBetweenSubmissions)
	for _, dirEntry := range dirList {
		dirPath := filepath.Join(a.conf.TargetDir, dirEntry.Name())
		shouldSleep, err := a.ProcessSample(dirPath)
		//log.Printf("After Process Sample: %v, %v", shouldSleep, err)
		if err != nil {
			log.Print(err)
		}
		if !shouldSleep {
			continue
		}
		sleep := time.Until(nextTime)
		nextTime = nextTime.Add(a.conf.PauseBetweenSubmissions)
		log.Printf("Sleep between samples %v", sleep)
		time.Sleep(sleep)
	}
	return nil
}

func (a *VTAnalysis) ProcessSample(dirPath string) (sleep bool, err error) {
	//log.Printf("Process %s", dirPath)
	sleep = false

	jsonFileName := "virustotal_analysis.json"
	jsonFilePath := filepath.Join(dirPath, jsonFileName)
	_, err = os.Stat(jsonFilePath)
	if err == nil {
		//log.Printf("Already have %s. In %s", jsonFileName, dirPath)
		return
	}
	vtupload := "virustotalupload.json"
	vtuploadPath := filepath.Join(dirPath, vtupload)
	var info os.FileInfo
	info, err = os.Stat(vtuploadPath)
	if err != nil {
		err = nil
		//log.Printf("Missing %s. Skip %s", vtupload, dirPath)
		return
	}
	tooEarly := info.ModTime().Add(10 * time.Minute).After(time.Now())
	if tooEarly {
		log.Printf("Too early for %s", dirPath)
		return
	}

	sha256, err := os.ReadFile(filepath.Join(dirPath, "sha256.txt"))
	if err != nil {
		return
	}

	sleep = true
	obj, err := a.client.GetObject(vt.URL("files/%s", sha256))
	if err != nil {
		return
	}
	log.Printf("Got analyis result for %s", dirPath)
	jsonData, err := obj.MarshalJSON()
	if err != nil {
		return
	}
	err = os.WriteFile(jsonFilePath, jsonData, 0600)
	return
}

/*

func lastAnalysisResult(client *vt.Client, sha256 string) (
	result *Result,
	err error) {
	result = nil
	obj, err := client.GetObject(vt.URL("files/%s", sha256))
	if err != nil {
		return
	}
	jsonData, err := obj.MarshalJSON()
	if err != nil {
		return
	}
	var rootData map[string]json.RawMessage
	err = json.Unmarshal([]byte(jsonData), &rootData)
	if err != nil {
		err = fmt.Errorf("json.Unmarshal: %w", err)
		return
	}
	attributes, ok := rootData["attributes"]
	if !ok {
		err = fmt.Errorf("missing attributes")
		return
	}
	var attributesData map[string]json.RawMessage

	err = json.Unmarshal(attributes, &attributesData)
	if err != nil {
		err = fmt.Errorf("json.Unmarshal: %w", err)
		return
	}
	firstSubmissionDateBytes, ok := attributesData["first_submission_date"]
	if !ok {
		err = fmt.Errorf("missing first_submission_date")
		return
	}
	var firstSubmissionDateInt64 uint64
	firstSubmissionDateInt64, err = strconv.ParseUint(string(firstSubmissionDateBytes), 10, 64)
	if err != nil {
		err = fmt.Errorf("%s: wrong last_analysis_date value", string(firstSubmissionDateBytes))
		return
	}
	lastAnalysisDateBytes, ok := attributesData["last_analysis_date"]
	if !ok {
		err = fmt.Errorf("missing last_analysis_date")
		return
	}
	var lastAnalysisDateInt64 uint64
	lastAnalysisDateInt64, err = strconv.ParseUint(string(lastAnalysisDateBytes), 10, 64)
	if err != nil {
		err = fmt.Errorf("%s: wrong last_analysis_date value", string(lastAnalysisDateBytes))
		return
	}
	lastAnalysisResultsBytes, ok := attributesData["last_analysis_results"]
	if !ok {
		err = fmt.Errorf("missing last_analysis_results")
		return
	}
	var lastAnalysisData map[string]json.RawMessage
	err = json.Unmarshal(lastAnalysisResultsBytes, &lastAnalysisData)
	if err != nil {
		err = fmt.Errorf("json.Unmarshal: %w", err)
		return
	}
	result = NewResult()
	result.sha256 = sha256
	result.createdDate = time.Now()
	result.firstSubmissionDate = time.Unix(int64(firstSubmissionDateInt64), 0)
	result.lastAnalysisDate = time.Unix(int64(lastAnalysisDateInt64), 0)
	for _, resultBytes := range lastAnalysisData {
		var r AnalysisResult
		json.Unmarshal(resultBytes, &r)
		result.engines[r.EngineName] = r.Result
	}
	return
}

type Result struct {
	sha256              string
	createdDate         time.Time
	firstSubmissionDate time.Time
	lastAnalysisDate    time.Time
	engines             map[string]string
}

func NewResult() *Result {
	return &Result{
		engines: make(map[string]string),
	}
}*/

/*
func (r *Result) Merge(allEngines map[string]struct{}) {
	for e := range allEngines {
		_, ok := r.engines[e]
		if !ok {
			r.engines[e] = "missing"
		}
	}
}

func (r *Result) Extend(allEngines map[string]struct{}) {
	for e := range r.engines {
		allEngines[e] = struct{}{}
	}
}

func (r *Result) CSV(allEngines map[string]struct{}) string {
	var sb strings.Builder
	fsd := r.firstSubmissionDate.Format(timeLayout)
	lad := r.lastAnalysisDate.Format(timeLayout)
	w := r.when.Format(timeLayout)
	sb.WriteString(fmt.Sprintf("%s;%s;%s;%s", r.sha256, w, fsd, lad))
	r.Merge(allEngines)
	keys := r.AllEngines()
	for _, k := range keys {
		sb.WriteString(";")
		sb.WriteString(r.engines[k])
	}
	sb.WriteString("\n")
	return sb.String()
}

func (r *Result) AllEngines() []string {
	keys := make([]string, 0, len(r.engines))
	for k := range r.engines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type CSV struct {
	headers []string
	engines map[string]struct{}
	results []*Result
}

func NewCSV() *CSV {
	return &CSV{
		headers: []string{"SHA256", "time", "First Submission Date", "Last Analysis Date"},
	}
}

func (c *CSV) LoadFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	return c.Load(f)
}

func (c *CSV) Load(r io.Reader) error {
	reader := bufio.NewReaderSize(r, 4*1024)
	n := 0
	for {
		line, isPrefix, err := reader.ReadLine()
		if err == io.EOF {
			return nil
		}
		if isPrefix {
			return fmt.Errorf("too long line: %s", line)
		}
		if n == 0 {
			c.ParseHeader(line)
		} else {
			c.ParseLine(line)
		}
		n++
	}
}

func (c *CSV) AddResult(r *Result) {
	c.results = append(c.results, r)
	r.Extend(c.engines)
}

func (c *CSV) Save(filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.SaveToWriter(f)
}

func (c *CSV) SaveToWriter(w io.Writer) error {
	h1 := strings.Join(c.headers, ";")
	h2 := strings.Join(c.engines, ";")
	h := h1 + ";" + h2 + "\n"
	_, err := w.Write([]byte(h))
	if err != nil {
		return err
	}
	for _, r := range c.results {
		_, err := w.Write([]byte(r.CSV(c.engines)))
		if err != nil {
			return err
		}
	}
	return nil
}

var ErrWrongHeader error = errors.New("wrong header")

func (c *CSV) ParseHeader(line []byte) error {
	l := string(line)
	n := 0
	for _, w := range strings.Split(l, ";") {
		if n < 4 {
			if c.headers[n] != w {
				return fmt.Errorf("%s: %w", w, ErrWrongHeader)
			}
		} else {
			c.engines[w] = struct{}{}
		}
		n++
	}
	return nil
}

func (c *CSV) ParseLine(line []byte) error {
	l := string(line)
	n := 0
	r := NewResult()
	var err error
	for _, w := range strings.Split(l, ";") {
		switch n {
		case 0:
			r.sha256 = w
		case 1:
			r.when, err = time.Parse(timeLayout, w)
			if err != nil {
				return err
			}
		case 2:
			r.firstSubmissionDate, err = time.Parse(timeLayout, w)
			if err != nil {
				return err
			}
		case 3:
			r.lastAnalysisDate, err = time.Parse(timeLayout, w)
			if err != nil {
				return err
			}
		default:
			r.engines[c.engines[n-4]] = w
		}
		n++
	}
	c.results = append(c.results, r)
	return nil
}
*/

var jsonExample = `{
  "id": "f7f702f7433243a69bbddbb632b56d676c5fdd1b2ce3970c16baea1ae38817a7",
  "type": "file",
  "attributes": {
    "creation_date": 1433528374,
    "crowdsourced_yara_results": [
      {
        "author": "John Lambert @JohnLaTwC",
        "description": "Detects Excel4 macro use with auto open / close",
        "rule_name": "SUSP_Excel4Macro_AutoOpen",
        "ruleset_id": "0000c36aca",
        "ruleset_name": "gen_Excel4Macro_Sharpshooter",
        "source": "https://github.com/Neo23x0/signature-base"
      }
    ],
    "first_submission_date": 1636464450,
    "last_analysis_date": 1636546503,
    "last_analysis_results": {
      "ALYac": {
        "category": "undetected",
        "engine_name": "ALYac",
        "engine_update": "20211110",
        "engine_version": "1.1.3.1",
        "method": "blacklist",
        "result": null
      },
      "APEX": {
        "category": "type-unsupported",
        "engine_name": "APEX",
        "engine_update": "20211110",
        "engine_version": "6.228",
        "method": "blacklist",
        "result": null
      },
      "AVG": {
        "category": "malicious",
        "engine_name": "AVG",
        "engine_update": "20211110",
        "engine_version": "21.1.5827.0",
        "method": "blacklist",
        "result": "XLS:Nastya [Trj]"
      },
      "Acronis": {
        "category": "undetected",
        "engine_name": "Acronis",
        "engine_update": "20210512",
        "engine_version": "1.1.1.82",
        "method": "blacklist",
        "result": null
      },
      "Ad-Aware": {
        "category": "malicious",
        "engine_name": "Ad-Aware",
        "engine_update": "20211110",
        "engine_version": "3.0.21.193",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP"
      },
      "AhnLab-V3": {
        "category": "undetected",
        "engine_name": "AhnLab-V3",
        "engine_update": "20211110",
        "engine_version": "3.21.1.10219",
        "method": "blacklist",
        "result": null
      },
      "Alibaba": {
        "category": "type-unsupported",
        "engine_name": "Alibaba",
        "engine_update": "20190527",
        "engine_version": "0.3.0.5",
        "method": "blacklist",
        "result": null
      },
      "Antiy-AVL": {
        "category": "undetected",
        "engine_name": "Antiy-AVL",
        "engine_update": "20211110",
        "engine_version": "3.0.0.1",
        "method": "blacklist",
        "result": null
      },
      "Arcabit": {
        "category": "malicious",
        "engine_name": "Arcabit",
        "engine_update": "20211110",
        "engine_version": "1.0.0.888",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP"
      },
      "Avast": {
        "category": "malicious",
        "engine_name": "Avast",
        "engine_update": "20211110",
        "engine_version": "21.1.5827.0",
        "method": "blacklist",
        "result": "XLS:Nastya [Trj]"
      },
      "Avast-Mobile": {
        "category": "type-unsupported",
        "engine_name": "Avast-Mobile",
        "engine_update": "20211110",
        "engine_version": "211110-00",
        "method": "blacklist",
        "result": null
      },
      "Avira": {
        "category": "malicious",
        "engine_name": "Avira",
        "engine_update": "20211110",
        "engine_version": "8.3.3.12",
        "method": "blacklist",
        "result": "W97M/YAV.Minerva.cjfjz"
      },
      "Baidu": {
        "category": "undetected",
        "engine_name": "Baidu",
        "engine_update": "20190318",
        "engine_version": "1.0.0.2",
        "method": "blacklist",
        "result": null
      },
      "BitDefender": {
        "category": "malicious",
        "engine_name": "BitDefender",
        "engine_update": "20211110",
        "engine_version": "7.2",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP"
      },
      "BitDefenderFalx": {
        "category": "type-unsupported",
        "engine_name": "BitDefenderFalx",
        "engine_update": "20210610",
        "engine_version": "2.0.936",
        "method": "blacklist",
        "result": null
      },
      "BitDefenderTheta": {
        "category": "undetected",
        "engine_name": "BitDefenderTheta",
        "engine_update": "20211104",
        "engine_version": "7.2.37796.0",
        "method": "blacklist",
        "result": null
      },
      "Bkav": {
        "category": "undetected",
        "engine_name": "Bkav",
        "engine_update": "20211109",
        "engine_version": "1.3.0.9899",
        "method": "blacklist",
        "result": null
      },
      "CAT-QuickHeal": {
        "category": "undetected",
        "engine_name": "CAT-QuickHeal",
        "engine_update": "20211110",
        "engine_version": "14.00",
        "method": "blacklist",
        "result": null
      },
      "CMC": {
        "category": "undetected",
        "engine_name": "CMC",
        "engine_update": "20211026",
        "engine_version": "2.10.2019.1",
        "method": "blacklist",
        "result": null
      },
      "ClamAV": {
        "category": "undetected",
        "engine_name": "ClamAV",
        "engine_update": "20211110",
        "engine_version": "0.104.1.0",
        "method": "blacklist",
        "result": null
      },
      "Comodo": {
        "category": "undetected",
        "engine_name": "Comodo",
        "engine_update": "20211102",
        "engine_version": "34044",
        "method": "blacklist",
        "result": null
      },
      "CrowdStrike": {
        "category": "type-unsupported",
        "engine_name": "CrowdStrike",
        "engine_update": "20210203",
        "engine_version": "1.0",
        "method": "blacklist",
        "result": null
      },
      "Cybereason": {
        "category": "timeout",
        "engine_name": "Cybereason",
        "engine_update": "20210330",
        "engine_version": null,
        "method": "blacklist",
        "result": null
      },
      "Cylance": {
        "category": "type-unsupported",
        "engine_name": "Cylance",
        "engine_update": "20211110",
        "engine_version": "2.3.1.101",
        "method": "blacklist",
        "result": null
      },
      "Cynet": {
        "category": "malicious",
        "engine_name": "Cynet",
        "engine_update": "20211110",
        "engine_version": "4.0.0.27",
        "method": "blacklist",
        "result": "Malicious (score: 99)"
      },
      "Cyren": {
        "category": "malicious",
        "engine_name": "Cyren",
        "engine_update": "20211110",
        "engine_version": "6.3.0.2",
        "method": "blacklist",
        "result": "XF/Agent.AI.gen!Camelot"
      },
      "DrWeb": {
        "category": "malicious",
        "engine_name": "DrWeb",
        "engine_update": "20211110",
        "engine_version": "7.0.52.8270",
        "method": "blacklist",
        "result": "Exploit.Siggen3.21799"
      },
      "ESET-NOD32": {
        "category": "malicious",
        "engine_name": "ESET-NOD32",
        "engine_update": "20211110",
        "engine_version": "24268",
        "method": "blacklist",
        "result": "DOC/TrojanDownloader.Agent.DMS"
      },
      "Elastic": {
        "category": "type-unsupported",
        "engine_name": "Elastic",
        "engine_update": "20211005",
        "engine_version": "4.0.29",
        "method": "blacklist",
        "result": null
      },
      "Emsisoft": {
        "category": "malicious",
        "engine_name": "Emsisoft",
        "engine_update": "20211110",
        "engine_version": "2021.5.0.7597",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP (B)"
      },
      "F-Secure": {
        "category": "undetected",
        "engine_name": "F-Secure",
        "engine_update": "20211110",
        "engine_version": "12.0.86.52",
        "method": "blacklist",
        "result": null
      },
      "FireEye": {
        "category": "malicious",
        "engine_name": "FireEye",
        "engine_update": "20211110",
        "engine_version": "32.44.1.0",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP"
      },
      "Fortinet": {
        "category": "malicious",
        "engine_name": "Fortinet",
        "engine_update": "20211110",
        "engine_version": "6.2.142.0",
        "method": "blacklist",
        "result": "XF/CoinMiner.Z!tr"
      },
      "GData": {
        "category": "malicious",
        "engine_name": "GData",
        "engine_update": "20211110",
        "engine_version": "A:25.31304B:27.25101",
        "method": "blacklist",
        "result": "Generic.Trojan.Agent.4QGXOS"
      },
      "Gridinsoft": {
        "category": "undetected",
        "engine_name": "Gridinsoft",
        "engine_update": "20211110",
        "engine_version": "1.0.62.161",
        "method": "blacklist",
        "result": null
      },
      "Ikarus": {
        "category": "malicious",
        "engine_name": "Ikarus",
        "engine_update": "20211110",
        "engine_version": "0.1.5.2",
        "method": "blacklist",
        "result": "Trojan-Downloader.XLM.Agent"
      },
      "Jiangmin": {
        "category": "undetected",
        "engine_name": "Jiangmin",
        "engine_update": "20211108",
        "engine_version": "16.0.100",
        "method": "blacklist",
        "result": null
      },
      "K7AntiVirus": {
        "category": "undetected",
        "engine_name": "K7AntiVirus",
        "engine_update": "20211110",
        "engine_version": "11.227.39241",
        "method": "blacklist",
        "result": null
      },
      "K7GW": {
        "category": "undetected",
        "engine_name": "K7GW",
        "engine_update": "20211110",
        "engine_version": "11.227.39242",
        "method": "blacklist",
        "result": null
      },
      "Kaspersky": {
        "category": "malicious",
        "engine_name": "Kaspersky",
        "engine_update": "20211110",
        "engine_version": "21.0.1.45",
        "method": "blacklist",
        "result": "UDS:DangerousObject.Multi.Generic"
      },
      "Kingsoft": {
        "category": "undetected",
        "engine_name": "Kingsoft",
        "engine_update": "20211110",
        "engine_version": "2017.9.26.565",
        "method": "blacklist",
        "result": null
      },
      "Lionic": {
        "category": "malicious",
        "engine_name": "Lionic",
        "engine_update": "20211110",
        "engine_version": "4.2",
        "method": "blacklist",
        "result": "Trojan.MSOffice.Generic.4!c"
      },
      "MAX": {
        "category": "malicious",
        "engine_name": "MAX",
        "engine_update": "20211110",
        "engine_version": "2019.9.16.1",
        "method": "blacklist",
        "result": "malware (ai score=87)"
      },
      "Malwarebytes": {
        "category": "undetected",
        "engine_name": "Malwarebytes",
        "engine_update": "20211110",
        "engine_version": "4.2.2.27",
        "method": "blacklist",
        "result": null
      },
      "MaxSecure": {
        "category": "undetected",
        "engine_name": "MaxSecure",
        "engine_update": "20211110",
        "engine_version": "1.0.0.1",
        "method": "blacklist",
        "result": null
      },
      "McAfee": {
        "category": "malicious",
        "engine_name": "McAfee",
        "engine_update": "20211110",
        "engine_version": "6.0.6.653",
        "method": "blacklist",
        "result": "X97M/Downloader.mf"
      },
      "McAfee-GW-Edition": {
        "category": "malicious",
        "engine_name": "McAfee-GW-Edition",
        "engine_update": "20211110",
        "engine_version": "v2019.1.2+3728",
        "method": "blacklist",
        "result": "X97M/Downloader.mf"
      },
      "MicroWorld-eScan": {
        "category": "malicious",
        "engine_name": "MicroWorld-eScan",
        "engine_update": "20211110",
        "engine_version": "14.0.409.0",
        "method": "blacklist",
        "result": "Trojan.DOC.Agent.AXP"
      },
      "Microsoft": {
        "category": "malicious",
        "engine_name": "Microsoft",
        "engine_update": "20211110",
        "engine_version": "1.1.18700.4",
        "method": "blacklist",
        "result": "TrojanDownloader:O97M/EncDoc.ASY!MTB"
      },
      "NANO-Antivirus": {
        "category": "undetected",
        "engine_name": "NANO-Antivirus",
        "engine_update": "20211110",
        "engine_version": "1.0.146.25409",
        "method": "blacklist",
        "result": null
      },
      "Paloalto": {
        "category": "type-unsupported",
        "engine_name": "Paloalto",
        "engine_update": "20211110",
        "engine_version": "1.0",
        "method": "blacklist",
        "result": null
      },
      "Panda": {
        "category": "undetected",
        "engine_name": "Panda",
        "engine_update": "20211109",
        "engine_version": "4.6.4.2",
        "method": "blacklist",
        "result": null
      },
      "Rising": {
        "category": "malicious",
        "engine_name": "Rising",
        "engine_update": "20211110",
        "engine_version": "25.0.0.26",
        "method": "blacklist",
        "result": "Downloader.Agent/XLM!1.DA73 (CLASSIC)"
      },
      "SUPERAntiSpyware": {
        "category": "undetected",
        "engine_name": "SUPERAntiSpyware",
        "engine_update": "20211106",
        "engine_version": "5.6.0.1032",
        "method": "blacklist",
        "result": null
      },
      "Sangfor": {
        "category": "malicious",
        "engine_name": "Sangfor",
        "engine_update": "20211103",
        "engine_version": "2.9.0.0",
        "method": "blacklist",
        "result": "Malware.Generic-XLM.Save.ma29"
      },
      "SentinelOne": {
        "category": "undetected",
        "engine_name": "SentinelOne",
        "engine_update": "20211028",
        "engine_version": "6.3.0.2",
        "method": "blacklist",
        "result": null
      },
      "Sophos": {
        "category": "malicious",
        "engine_name": "Sophos",
        "engine_update": "20211110",
        "engine_version": "1.4.1.0",
        "method": "blacklist",
        "result": "Mal/DocDl-M"
      },
      "Symantec": {
        "category": "malicious",
        "engine_name": "Symantec",
        "engine_update": "20211110",
        "engine_version": "1.16.0.0",
        "method": "blacklist",
        "result": "Trojan.Gen.MBT"
      },
      "SymantecMobileInsight": {
        "category": "type-unsupported",
        "engine_name": "SymantecMobileInsight",
        "engine_update": "20210126",
        "engine_version": "2.0",
        "method": "blacklist",
        "result": null
      },
      "TACHYON": {
        "category": "undetected",
        "engine_name": "TACHYON",
        "engine_update": "20211110",
        "engine_version": "2021-11-10.02",
        "method": "blacklist",
        "result": null
      },
      "Tencent": {
        "category": "malicious",
        "engine_name": "Tencent",
        "engine_update": "20211110",
        "engine_version": "1.0.0.1",
        "method": "blacklist",
        "result": "Trojan.MsOffice.Macro40.11014080"
      },
      "Trapmine": {
        "category": "type-unsupported",
        "engine_name": "Trapmine",
        "engine_update": "20200727",
        "engine_version": "3.5.0.1023",
        "method": "blacklist",
        "result": null
      },
      "TrendMicro": {
        "category": "undetected",
        "engine_name": "TrendMicro",
        "engine_update": "20211110",
        "engine_version": "11.0.0.1006",
        "method": "blacklist",
        "result": null
      },
      "TrendMicro-HouseCall": {
        "category": "undetected",
        "engine_name": "TrendMicro-HouseCall",
        "engine_update": "20211110",
        "engine_version": "10.0.0.1040",
        "method": "blacklist",
        "result": null
      },
      "Trustlook": {
        "category": "type-unsupported",
        "engine_name": "Trustlook",
        "engine_update": "20211110",
        "engine_version": "1.0",
        "method": "blacklist",
        "result": null
      },
      "VBA32": {
        "category": "undetected",
        "engine_name": "VBA32",
        "engine_update": "20211110",
        "engine_version": "5.0.0",
        "method": "blacklist",
        "result": null
      },
      "VIPRE": {
        "category": "undetected",
        "engine_name": "VIPRE",
        "engine_update": "20211110",
        "engine_version": "96848",
        "method": "blacklist",
        "result": null
      },
      "ViRobot": {
        "category": "malicious",
        "engine_name": "ViRobot",
        "engine_update": "20211110",
        "engine_version": "2014.3.20.0",
        "method": "blacklist",
        "result": "XLS.Z.Agent.129024.NQ"
      },
      "Webroot": {
        "category": "type-unsupported",
        "engine_name": "Webroot",
        "engine_update": "20211110",
        "engine_version": "1.0.0.403",
        "method": "blacklist",
        "result": null
      },
      "Yandex": {
        "category": "undetected",
        "engine_name": "Yandex",
        "engine_update": "20211110",
        "engine_version": "5.5.2.24",
        "method": "blacklist",
        "result": null
      },
      "Zillya": {
        "category": "undetected",
        "engine_name": "Zillya",
        "engine_update": "20211110",
        "engine_version": "2.0.0.4493",
        "method": "blacklist",
        "result": null
      },
      "Zoner": {
        "category": "undetected",
        "engine_name": "Zoner",
        "engine_update": "20211109",
        "engine_version": "2.2.2.0",
        "method": "blacklist",
        "result": null
      },
      "eGambit": {
        "category": "type-unsupported",
        "engine_name": "eGambit",
        "engine_update": "20211110",
        "engine_version": null,
        "method": "blacklist",
        "result": null
      }
    },
    "last_analysis_stats": {
      "confirmed-timeout": 0,
      "failure": 0,
      "harmless": 0,
      "malicious": 28,
      "suspicious": 0,
      "timeout": 1,
      "type-unsupported": 13,
      "undetected": 31
    },
    "last_modification_date": 1636555603,
    "last_submission_date": 1636546503,
    "magic": "CDF V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1251, Author: , Last Saved By: , Name of Creating Application: Microsoft Excel, Create Time/Date: Thu Jun 04 18:19:34 2015, Last Saved Time/Date: Mon Nov 08 07:24:59 2021, Security: 0",
    "md5": "3bebc26dd21083aa83a764f14da72f6d",
    "meaningful_name": "9633c5d1fbe4b3d3b8dc326f0f0c16ea70b0c451.xls",
    "names": [
      "9633c5d1fbe4b3d3b8dc326f0f0c16ea70b0c451.xls"
    ],
    "popular_threat_classification": {
      "popular_threat_category": [
        {
          "count": 11,
          "value": "trojan"
        },
        {
          "count": 6,
          "value": "downloader"
        }
      ],
      "popular_threat_name": [
        {
          "count": 2,
          "value": "x97m"
        },
        {
          "count": 2,
          "value": "msoffice"
        },
        {
          "count": 2,
          "value": "nastya"
        }
      ],
      "suggested_threat_label": "trojan.x97m/msoffice"
    },
    "reputation": 0,
    "sandbox_verdicts": {
      "BitDam ATP": {
        "category": "malicious",
        "malware_classification": [
          "MALWARE"
        ],
        "sandbox_name": "BitDam ATP"
      }
    },
    "sha1": "9633c5d1fbe4b3d3b8dc326f0f0c16ea70b0c451",
    "sha256": "f7f702f7433243a69bbddbb632b56d676c5fdd1b2ce3970c16baea1ae38817a7",
    "size": 129024,
    "ssdeep": "3072:YKpb8rGYrMPe3q7Q0XV5xtezEsi8/dgL5yVceeiE/RD/oU2/zLWQtt:YKpb8rGYrMPe3q7Q0XV5xtuEsi8/dgFM",
    "tags": [
      "xls"
    ],
    "times_submitted": 2,
    "tlsh": "T195C34953B655844EF616833814E743B1A2B2ED21CB5E0AC729D7BB227FBCDE05933852",
    "total_votes": {
      "harmless": 0,
      "malicious": 0
    },
    "trid": [
      {
        "file_type": "Microsoft Excel sheet",
        "probability": 80.2
      },
      {
        "file_type": "Generic OLE2 / Multistream Compound",
        "probability": 19.7
      }
    ],
    "type_description": "MS Excel Spreadsheet",
    "type_extension": "xls",
    "type_tag": "xls",
    "unique_sources": 2,
    "vhash": "0cc11d97e5cfc9baa1ad4b77131befc5"
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/files/f7f702f7433243a69bbddbb632b56d676c5fdd1b2ce3970c16baea1ae38817a7"
  }
}`
