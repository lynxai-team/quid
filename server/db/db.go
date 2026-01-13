package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/jmoiron/sqlx"

	// pg import.
	_ "github.com/lib/pq"

	"github.com/lynxai-team/emo"
)

var db *sqlx.DB

var log = emo.NewZone("db")

// Connect : connect to the db.
func Connect(url string) error {
	url = strings.Replace(url, "postgresql://", "postgres://", 1)
	_db, err := sqlx.Connect("postgres", url)
	if err != nil {
		log.Warn(err)
		return err
	}

	db = _db
	return nil
}

// DropTablesIndexes deletes all tables and indexes from DB.
func DropTablesIndexes() error {
	result, err := db.Exec(dropAll)
	if err != nil {
		log.Warn(err)
		return err
	}

	if result == nil {
		return errors.New("DropTablesIndexes: result is nil")
	}

	n, err := result.RowsAffected()
	if err != nil {
		log.Warn("DropTablesIndexes RowsAffected:", err)
		return err
	}

	log.Dataf("Dropped tables and indexes (if exist). RowsAffected=%d", n)
	return nil
}

// DropDatabase executes "DROP DATABASE $POSTGRES_DB;".
func DropDatabase(dbName string) error {
	if p := isAlphaNum(dbName); p >= 0 {
		return fmt.Errorf("the database name must be composed of letters and digits only, "+
			"but got %q containing an invalid character at position %d", dbName, p)
	}

	result, err := db.Exec("DROP DATABASE " + dbName + ";")
	if err != nil {
		log.Warn(err)
		return err
	}

	if result == nil {
		return errors.New("DropDatabase: result is nil")
	}

	n, err := result.RowsAffected()
	if err != nil {
		log.Warn("DropDatabase RowsAffected:", err)
		return err
	}

	log.Dataf("Dropped database. RowsAffected=%d", n)
	return nil
}

// CreateTablesIndexesIfMissing : execute the schema.
func CreateTablesIndexesIfMissing() error {
	result, err := db.Exec(schema)
	if err != nil {
		log.Warn(err)
		return err
	}

	if result == nil {
		return errors.New("CreateTablesIndexes: result is nil")
	}

	n, err := result.RowsAffected()
	if err != nil {
		log.Warn("CreateTablesIndexes RowsAffected:", err)
		return err
	}

	log.Dataf("Created tables and indexes (if not exist). RowsAffected=%d", n)
	return nil
}

func isAlphaNum(s string) int {
	for i, r := range s {
		if unicode.IsLetter(r) {
			continue
		}
		if unicode.IsDigit(r) {
			continue
		}
		return i
	}
	return -1
}

func getFirstID(name string, rows *sql.Rows) (int64, error) {
	if !rows.Next() {
		return 0, log.S(1).QueryErrorf("no name=%q", name).Err()
	}

	var idAny any
	err := rows.Scan(&idAny)
	if err != nil {
		log.S(1).QueryError("name=", name, ":", err)
		return 0, err
	}

	id, ok := idAny.(int64)
	if !ok {
		return 0, log.S(1).QueryError("name=", name, ": cannot convert", idAny, " into int64").Err()
	}

	return id, nil
}
