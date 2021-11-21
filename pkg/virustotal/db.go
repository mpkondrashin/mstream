package virustotal

import (
	"database/sql"
	"fmt"
	"io"
	"strings"

	// sqlite support
	_ "modernc.org/sqlite"
)

const CSVSep = ";"

type DB struct {
	DBPath string
	db     *sql.DB
}

// NewDB - create new state database
func NewDB(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dbPath, err)
	}
	CreateTable := `CREATE TABLE IF NOT EXISTS vt (
		sha256 TEXT PRIMARY KEY,
		first_submission_date TEXT,
		last_analysis_date TEXT,
		created_date TEXT
		);
		CREATE TABLE IF NOT EXISTS engine (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE
		);
		CREATE TABLE IF NOT EXISTS malware (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE
		);
		CREATE TABLE IF NOT EXISTS detection (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			malware INTEGER,
			engine INTEGER,
			sha256 TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS vt_idx ON vt (sha256)`
	if _, err := db.Exec(CreateTable); err != nil {
		return nil, fmt.Errorf("%s: %w", dbPath, err)
	}
	return &DB{
		dbPath, db,
	}, nil
}

func (d *DB) AddResult(sha256, first_submission_date, last_analysis_date,
	created_date string, callback func(add func(engine, result string) error) error) error {
	tx, err := d.db.Begin()
	if err != nil {
		return d.fail(err)
	}
	defer tx.Rollback()
	Insert := "INSERT OR REPLACE INTO vt (sha256, first_submission_date, last_analysis_date, created_date ) " +
		"VALUES ($1, $2, $3, $4)"
	_, err = tx.Exec(Insert, sha256, first_submission_date, last_analysis_date, created_date)
	if err != nil {
		return d.fail(err)
	}
	add := func(engine, result string) error {
		engineId, err := getOrAddEngineID(tx, engine)
		if err != nil {
			return d.fail(err)
		}
		malwareID, err := getOrAddMalwareID(tx, result)
		if err != nil {
			return d.fail(err)
		}
		Insert = "INSERT OR REPLACE INTO detection (malware, engine, sha256) " +
			"VALUES ($1, $2, $3)"
		_, err = tx.Exec(Insert, malwareID, engineId, sha256)
		return d.fail(err)
	}
	err = callback(add)
	if err != nil {
		return err
	}
	return d.fail(tx.Commit())
}

func (d *DB) CSV(w io.Writer) error {
	tx, err := d.db.Begin()
	if err != nil {
		return d.fail(err)
	}
	defer tx.Rollback()
	err = d.HeaderCSV(tx, w)
	if err != nil {
		return err
	}
	engineList, err := getEngineIDsOrder(tx)
	if err != nil {
		return d.fail(err)
	}
	Select := "SELECT sha256, first_submission_date, last_analysis_date, created_date FROM vt " +
		"ORDER BY created_date ASC"
	row, err := tx.Query(Select)
	if err != nil {
		return d.fail(err)
	}
	for row.Next() {
		var prefix [4]string
		//var sha256 string
		//var fsd string
		//var lad string
		//var cd string
		//err := row.Scan(&sha256, &fsd, &lad, &cd)
		err := row.Scan(&prefix[0], &prefix[1], &prefix[2], &prefix[3])
		if err != nil {
			return d.fail(err)
		}
		_, err = w.Write([]byte(strings.Join(prefix[:], CSVSep)))
		if err != nil {
			return err
		}
		for _, engineID := range engineList {
			r, err := malwareNameForSHA256AndEngine(tx, prefix[0], engineID)
			if err != nil {
				return d.fail(err)
			}
			_, err = w.Write([]byte(CSVSep + r))
			if err != nil {
				return err
			}
		}
		_, err = w.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}
	return d.fail(tx.Commit())
}

func (d *DB) HeaderCSV(tx *sql.Tx, w io.Writer) error {
	firstColumns := []string{
		"sha256", "First Submission", "Last Analysis", "Created",
	}
	_, err := w.Write([]byte(strings.Join(firstColumns, CSVSep)))
	if err != nil {
		return err
	}
	Select := "SELECT name FROM engine ORDER BY name ASC"
	row, err := tx.Query(Select)
	if err != nil {
		return d.fail(err)
	}
	for row.Next() {
		var engineName string
		err := row.Scan(&engineName)
		if err != nil {
			return d.fail(err)
		}
		_, err = w.Write([]byte(CSVSep + engineName))
		if err != nil {
			return err
		}
	}
	_, err = w.Write([]byte("\n"))
	if err != nil {
		return err
	}
	return nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) fail(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", d.DBPath, err)
}

func getOrAddID(tx *sql.Tx, table, value string) (id int64, err error) {
	Select := fmt.Sprintf("SELECT id FROM %s WHERE name=$1", table)
	row := tx.QueryRow(Select, value)
	err = row.Scan(&id)
	if err == nil {
		return
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	Insert := fmt.Sprintf("INSERT OR REPLACE INTO %s (name) "+
		"VALUES ($1)", table)
	res, err := tx.Exec(Insert, value)
	if err != nil {
		return 0, err
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return
}

func getOrAddEngineID(tx *sql.Tx, engineName string) (engineID int64, err error) {
	return getOrAddID(tx, "engine", engineName)
}

func getOrAddMalwareID(tx *sql.Tx, malwareName string) (engineID int64, err error) {
	return getOrAddID(tx, "malware", malwareName)
}

func getName(tx *sql.Tx, table string, id int64) (name string, err error) {
	Select := fmt.Sprintf("SELECT name FROM %s WHERE id=$1", table)
	row := tx.QueryRow(Select, id)
	err = row.Scan(&name)
	return
}

/*
func getEngineName(tx *sql.Tx, id int64) (string, error) {
	return getName(tx, "engine", id)
}
*/

func getMalwareName(tx *sql.Tx, id int64) (string, error) {
	return getName(tx, "malware", id)
}

func getEngineIDsOrder(tx *sql.Tx) (list []int64, err error) {
	Select := "SELECT id FROM engine ORDER BY name ASC"
	row, err := tx.Query(Select)
	if err != nil {
		return nil, err
	}
	for row.Next() {
		var id int64
		err := row.Scan(&id)
		if err != nil {
			return nil, err
		}
		list = append(list, id)
	}
	return
}

func malwareNameForSHA256AndEngine(tx *sql.Tx, sha256 string, engineID int64) (string, error) {
	Select := "SELECT malware FROM detection WHERE engine=$1 AND sha256=$2"
	row := tx.QueryRow(Select, engineID, sha256)
	var malwareID int64
	err := row.Scan(&malwareID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	malwareName, err := getMalwareName(tx, malwareID)
	if err != nil {
		return "", err
	}
	return malwareName, nil
}
