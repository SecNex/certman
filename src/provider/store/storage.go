package store

// StorageProvider defines the interface that any storage provider must implement
type StorageProvider interface {
	Get(path string) ([]byte, error)
	List(path string) ([]string, error)
	New(path string, data []byte) error
}

// Storage struct contains a StorageProvider
type Storage struct {
	Provider StorageProvider
}

// NewStorage initializes a new Storage with the given provider
func NewStorage(provider StorageProvider) *Storage {
	if provider == nil {
		return nil
	}
	return &Storage{
		Provider: provider,
	}
}
