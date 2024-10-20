package store

import (
	"log"
	"os"
)

type Local struct {
	Path string
}

func NewLocal(path string) *Local {
	log.Printf("Initializing local storage at: %s\n", path)
	return &Local{
		Path: path,
	}
}

func (l *Local) Get(path string) ([]byte, error) {
	log.Printf("Downloading file from local: %s\n", path)
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (l *Local) List(path string) ([]string, error) {
	log.Printf("Listing files in local: %s\n", path)
	dir, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var files []string

	for _, file := range dir {
		info, err := file.Info()
		if err != nil {
			return nil, err
		}
		log.Printf("Name: %s, Size: %d Bytes\n", file.Name(), info.Size())
		files = append(files, file.Name())
	}

	return files, nil
}

func (l *Local) New(path string, data []byte) error {
	log.Printf("Uploading file to local: %s\n", path)
	return os.WriteFile(path, data, 0644)
}
