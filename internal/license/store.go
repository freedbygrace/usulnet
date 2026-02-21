package license

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Store struct {
	path string
}

func NewStore(dataDir string) *Store {
	return &Store{
		path: filepath.Join(dataDir, "license.jwt"),
	}
}

func (s *Store) Save(jwt string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("license store: mkdir: %w", err)
	}
	if err := os.WriteFile(s.path, []byte(jwt+"\n"), 0600); err != nil {
		return fmt.Errorf("license store: write: %w", err)
	}
	return nil
}

func (s *Store) Load() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("license store: read: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *Store) Remove() error {
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("license store: remove: %w", err)
	}
	return nil
}

func (s *Store) Path() string {
	return s.path
}
