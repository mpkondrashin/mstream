package virustotal

import (
	"os"
	"path"
	"strings"
	"testing"

	//	_ "github.com/mattn/go-sqlite3"

	_ "modernc.org/sqlite"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func prepareDBTest() (*DB, error) {
	dir := "testing_db"
	check(os.RemoveAll(dir))
	check(os.Mkdir(dir, 0777))
	DBPath := path.Join(dir, "test.db")
	return NewDB(DBPath)
}

func TestVerdictCache_NewVerdictCache_Absent(t *testing.T) {
	DBPath := "non existent/test.db"
	_, err := NewDB(DBPath)
	if err == nil {
		t.Fatalf("Missing error")
	}
	//	expectation := "unable to open database file: no such file or directory"
	expectation := "unable to open database file"
	actual := err.Error()

	if !strings.Contains(actual, expectation) {
		t.Errorf("Expected \"%v\" but got \"%v\"", expectation, actual)
	}
}

func TestVerdictCache_NewVerdictCache(t *testing.T) {
	db, err := prepareDBTest()
	if err != nil {
		t.Errorf(err.Error())
	}
	defer db.Close()
}

func TestVerdictCache_AddResult(t *testing.T) {
	db, err := prepareDBTest()
	if err != nil {
		t.Errorf(err.Error())
	}
	defer db.Close()
	sha256 := "256"
	first_submission_date := "first date"
	last_analysis_date := "last date"
	created_date := "create date"
	err = db.AddResult(sha256, first_submission_date,
		last_analysis_date, created_date,
		func(add func(engine, result string) error) error {
			err := add("engine1", "result1")
			if err != nil {
				return err
			}
			err = add("engine2", "result2")
			if err != nil {
				return err
			}
			//	err = add("engine2", "resultXXX")
			//	if err != nil {
			//		return err
			//	}
			return nil
		})
	if err != nil {
		t.Errorf("db.AddResult: %v", err)
	}
	sb := new(strings.Builder)
	db.CSV(sb)
	expected := `sha256;First Submission;Last Analysis;Created;engine1;engine2
256;first date;last date;create date;result1;result2
`
	if sb.String() != expected {
		t.Errorf("Expected:\n%s\nBut got:\n%s", expected, sb.String())
	}
}
