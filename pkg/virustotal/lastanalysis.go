package virustotal

/*
import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

const TimeLayout = "2006-01-02 15:04:05" // -0700 MST"

func StoreResult(client *vt.Client, db *DB, sha256 string) error {
	result, err := LastAnalysisResult(client, sha256)
	if err != nil {
		return err
	}
	//fmt.Println(result.CSV([]string{}))

	return db.AddResult(sha256,
		result.firstSubmissionDate.Format(TimeLayout),
		result.lastAnalysisDate.Format(TimeLayout),
		result.createdDate.Format(TimeLayout),
		func(add func(engine, result string) error) error {
			for engine, malware := range result.engines {
				err := add(engine, malware)
				if err != nil {
					return err
				}
			}
			return nil
		})
}

func LastAnalysisResult(client *vt.Client, sha256 string) (
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
		r := new(AnalysisResult)
		json.Unmarshal(resultBytes, r)
		result.engines[r.EngineName] = r
	}
	return
}

type Result struct {
	sha256              string
	createdDate         time.Time
	firstSubmissionDate time.Time
	lastAnalysisDate    time.Time
	engines             map[string]*AnalysisResult
}

func NewResult() *Result {
	return &Result{
		engines: make(map[string]*AnalysisResult),
	}
}

type AnalysisResult struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineUpdate  string `json:"engine_update"`
	EngineVersion string `json:"engine_version"`
	Method        string `json:"method"`
	Result        string `json:"result"`
}
*/
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
