package database

import (
	"database/sql"
	"fmt"
	"os"
)

type LocalDatabaseProvider struct {
	ConnectionString ConnectionString
	Connection       *sql.DB
}

type ConnectionString struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	Secure   bool
}

func NewConnection(host string, port int, user, password, database string, secure bool) *ConnectionString {
	return &ConnectionString{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		Database: database,
		Secure:   secure,
	}
}

func (c *ConnectionString) String() string {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", c.Host, c.Port, c.User, c.Password, c.Database)
	if c.Secure {
		connStr += " sslmode=require"
	} else {
		connStr += " sslmode=disable"
	}
	return connStr
}

func NewLocalDatabaseProvider(connString ConnectionString) *LocalDatabaseProvider {
	connection, err := Connect(connString.String())
	if err != nil {
		panic(err)
	}
	return &LocalDatabaseProvider{
		ConnectionString: connString,
		Connection:       connection,
	}
}

func Connect(connString string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (l *LocalDatabaseProvider) Close() error {
	return l.Connection.Close()
}

func (l *LocalDatabaseProvider) Ping() bool {
	return l.Connection.Ping() == nil
}

func (l *LocalDatabaseProvider) Initialize(path string) error {
	data, err := ReadSqlFile(path)
	if err != nil {
		return err
	}

	_, err = l.Connection.Exec(string(data))
	if err != nil {
		return err
	}

	return nil
}

func ReadSqlFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
