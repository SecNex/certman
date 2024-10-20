package db

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type Database struct {
	*sql.DB
}

func Connect(dsn string) (*Database, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &Database{db}, nil
}

func (d *Database) Close() error {
	return d.DB.Close()
}

func (d *Database) Ping() bool {
	return d.DB.Ping() == nil
}
