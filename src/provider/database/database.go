package database

type Database struct {
	Provider DatabaseProvider
}

type DatabaseProvider interface {
	Ping() bool
	Close() error
	Initialize(path string) error
}

func NewDatabase(provider DatabaseProvider) *Database {
	if provider == nil {
		return nil
	}
	return &Database{
		Provider: provider,
	}
}
